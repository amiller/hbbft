use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::mem;
use std::rc::Rc;

use rand::{self, Rng};

use hbbft::crypto::{PublicKeySet, SecretKeySet};
use hbbft::messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

/// A node identifier. In the tests, nodes are simply numbered.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NodeUid(pub usize);

/// A "node" running an instance of the algorithm `D`.
pub struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// Incoming messages from other nodes that this node has not yet handled.
    pub queue: VecDeque<(D::NodeUid, D::Message)>,
    /// The values this node has output so far.
    outputs: Vec<D::Output>,
}

impl<D: DistAlgorithm> TestNode<D> {
    /// Returns the list of outputs received by this node.
    pub fn outputs(&self) -> &[D::Output] {
        &self.outputs
    }

    /// Returns whether the algorithm has terminated.
    #[allow(unused)] // Not used in all tests.
    pub fn terminated(&self) -> bool {
        self.algo.terminated()
    }

    /// Inputs a value into the instance.
    pub fn input(&mut self, input: D::Input) {
        self.algo.input(input).expect("input");
        self.outputs.extend(self.algo.output_iter());
    }

    /// Creates a new test node with the given broadcast instance.
    fn new(mut algo: D) -> TestNode<D> {
        let outputs = algo.output_iter().collect();
        TestNode {
            id: algo.our_id().clone(),
            algo,
            queue: VecDeque::new(),
            outputs,
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let (from_id, msg) = self.queue.pop_front().expect("message not found");
        debug!("Handling {:?} -> {:?}: {:?}", from_id, self.id, msg);
        self.algo
            .handle_message(&from_id, msg)
            .expect("handling message");
        self.outputs.extend(self.algo.output_iter());
    }

    /// Checks whether the node has messages to process
    fn is_idle(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A strategy for picking the next good node to handle a message.
pub enum MessageScheduler {
    /// Picks a random node.
    Random,
    /// Picks the first non-idle node.
    First,
}

impl MessageScheduler {
    /// Chooses a node to be the next one to handle a message.
    pub fn pick_node<D: DistAlgorithm>(
        &self,
        nodes: &BTreeMap<D::NodeUid, TestNode<D>>,
    ) -> D::NodeUid {
        match *self {
            MessageScheduler::First => nodes
                .iter()
                .find(|(_, node)| !node.queue.is_empty())
                .map(|(id, _)| id.clone())
                .expect("no more messages in queue"),
            MessageScheduler::Random => {
                let ids: Vec<D::NodeUid> = nodes
                    .iter()
                    .filter(|(_, node)| !node.queue.is_empty())
                    .map(|(id, _)| id.clone())
                    .collect();
                rand::thread_rng()
                    .choose(&ids)
                    .expect("no more messages in queue")
                    .clone()
            }
        }
    }
}

/// A message combined with a sender
pub struct MessageWithSender<D: DistAlgorithm> {
    /// The sender of the message
    pub sender: <D as DistAlgorithm>::NodeUid,
    /// The targeted message (recipient and message body)
    pub tm: TargetedMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>,
}

impl<D: DistAlgorithm> MessageWithSender<D> {
    /// Creates a new message with a sender
    pub fn new(
        sender: D::NodeUid,
        tm: TargetedMessage<D::Message, D::NodeUid>,
    ) -> MessageWithSender<D> {
        MessageWithSender { sender, tm }
    }
}

/// An adversary that can control a set of nodes and pick the next good node to receive a message.
///
/// See `TestNetwork::step()` for a more detailed description of its capabilities.
pub trait Adversary<D: DistAlgorithm> {
    /// Chooses a node to be the next one to handle a message
    ///
    /// Starvation is illegal, i.e. in every iteration a node that has pending incoming messages
    /// must be chosen.
    fn pick_node(&mut self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid;

    /// Called when a node controlled by the adversary receives a message
    fn push_message(&mut self, sender_id: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>);

    /// Produces a list of messages to be sent from the adversary's nodes
    fn step(&mut self) -> Vec<MessageWithSender<D>>;

    /// Initialize an adversary. This function's primary purpose is to inform the adversary over
    /// some aspects of the network, such as which nodes they control.
    fn init(&mut self, adv_nodes: &BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>>) {
        // default: does nothing
    }
}

/// An adversary whose nodes never send any messages.
pub struct SilentAdversary {
    scheduler: MessageScheduler,
}

impl SilentAdversary {
    /// Creates a new silent adversary with the given message scheduler.
    pub fn new(scheduler: MessageScheduler) -> SilentAdversary {
        SilentAdversary { scheduler }
    }
}

impl<D: DistAlgorithm> Adversary<D> for SilentAdversary {
    fn pick_node(&mut self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: D::NodeUid, _: TargetedMessage<D::Message, D::NodeUid>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<MessageWithSender<D>> {
        vec![] // No messages are sent.
    }
}

/// Return true with a certain `probability` ([0 .. 1.0])
fn randomly(probability: f32) -> bool {
    assert!(probability <= 1.0);
    assert!(probability >= 0.0);

    let mut rng = rand::thread_rng();
    rng.gen_range(0.0, 1.0) <= probability
}

#[test]
fn test_randomly() {
    assert!(randomly(1.0));
    assert!(!randomly(0.0));
}

// /// Picks a random element from a set
// fn pick_random<'a, T>(set: &BTreeSet<T>) -> Option<&T> {
//     let mut rng = rand::thread_rng();

//     // ensure gen_range does not panic
//     if set.len() == 0 {
//         return None;
//     }

//     let idx = rng.gen_range(0, set.len());

//     // note: this should never return None, since we checked the length beforehand
//     set.iter().nth(idx)
// }

/// An adversary that performs naive replay attacks
///
/// The adversary will randomly take a message that is sent to one of its nodes and re-send it to
/// a different node
pub struct RandomAdversary<D: DistAlgorithm> {
    /// The underlying scheduler used
    scheduler: MessageScheduler,

    /// Collects node ids seen by the adversary.
    known_node_ids: Vec<D::NodeUid>,

    /// Internal queue for messages to be returned on the next `Adversary::step()` call
    outgoing: Vec<MessageWithSender<D>>,

    /// Probability of a message replay
    p_replay: f32,
}

impl<D: DistAlgorithm> RandomAdversary<D> {
    /// Creates a new random adversary instance
    fn new(p_replay: f32) -> RandomAdversary<D> {
        RandomAdversary {
            // the random adversary, true to its name, always schedules randomnly
            scheduler: MessageScheduler::Random,
            known_node_ids: Vec::new(),
            outgoing: Vec::new(),
            p_replay: p_replay,
        }
    }
}

impl<D: DistAlgorithm> Adversary<D> for RandomAdversary<D> {
    fn pick_node(&mut self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        // we are a bit hamstrung by the current API in that we would usually like a set of node
        // ids available in `push_message`. the workaround is to "steal" them here for use later
        if self.known_node_ids.len() == 0 {
            self.known_node_ids = nodes.keys().cloned().collect();
        }

        // proceed by regularly picking a node
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>) {
        // if we have not discovered the network topology yet, abort
        if self.known_node_ids.len() == 0 {
            return;
        }

        // only replay a message in some cases
        if !randomly(self.p_replay) {
            return;
        }

        let TargetedMessage { message, target } = msg;

        match target {
            Target::All => {
                // ideally, we would want to handle broadcast messages as well; however the
                // adversary API is quite cumbersome at the moment in regards to access to the
                // network topology. to re-send a broadcast message from one of the attacker
                // controlled nodes, we would have to get a list of attacker controlled nodes
                // here and use a random one as the origin/sender
                return;
            }
            Target::Node(our_node_id) => {
                // choose a new target to send the message to
                // unwrap never fails, because we ensured that `known_node_ids` is non-empty earlier
                let mut rng = rand::thread_rng();
                let new_target_node = rng.choose(&self.known_node_ids).unwrap().clone();

                // TODO: we could randomly broadcast it instead, if we had access to topology
                //       information
                self.outgoing.push(MessageWithSender::new(
                    our_node_id,
                    TargetedMessage {
                        target: Target::Node(new_target_node),
                        message,
                    },
                ));
            }
        }
    }

    fn step(&mut self) -> Vec<MessageWithSender<D>> {
        // clear and send all messages
        let mut tmp = Vec::new();
        mem::swap(&mut tmp, &mut self.outgoing);
        tmp
    }
}

/// A collection of `TestNode`s representing a network.
///
/// Each TestNetwork type is tied to a specific adversary and a distributed algorithm. It consists
/// of a set of nodes, some of which are controlled by the adversary and some of which may be
/// observer nodes, as well as a set of threshold-cryptography public keys.
///
/// In addition to being able to participate correctly in the network using his nodes, the
/// adversary can:
///
/// 1. decide which node is the next one to make progress.
/// 2. send arbitrary messages to any node originating from one of the nodes they control
///
/// See the `step` function for details on actual operation of the network
pub struct TestNetwork<A: Adversary<D>, D: DistAlgorithm>
where
    <D as DistAlgorithm>::NodeUid: Hash,
{
    pub nodes: BTreeMap<D::NodeUid, TestNode<D>>,
    pub observer: TestNode<D>,
    pub adv_nodes: BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>>,
    pub pk_set: PublicKeySet,
    adversary: A,
}

impl<A: Adversary<D>, D: DistAlgorithm<NodeUid = NodeUid>> TestNetwork<A, D>
where
    D::Message: Clone,
{
    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    pub fn new<F, G>(
        good_num: usize,
        adv_num: usize,
        adversary: G,
        new_algo: F,
    ) -> TestNetwork<A, D>
    where
        F: Fn(Rc<NetworkInfo<NodeUid>>) -> D,
        G: Fn(BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>>) -> A,
    {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(adv_num, &mut rng);
        let pk_set = sk_set.public_keys();

        let node_ids: BTreeSet<NodeUid> = (0..(good_num + adv_num)).map(NodeUid).collect();
        let new_node_by_id = |NodeUid(i): NodeUid| {
            (
                NodeUid(i),
                TestNode::new(new_algo(Rc::new(NetworkInfo::new(
                    NodeUid(i),
                    node_ids.clone(),
                    sk_set.secret_key_share(i as u64),
                    pk_set.clone(),
                )))),
            )
        };
        let new_adv_node_by_id = |NodeUid(i): NodeUid| {
            (
                NodeUid(i),
                Rc::new(NetworkInfo::new(
                    NodeUid(i),
                    node_ids.clone(),
                    sk_set.secret_key_share(i as u64),
                    pk_set.clone(),
                )),
            )
        };
        let adv_nodes: BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>> = (good_num
            ..(good_num + adv_num))
            .map(NodeUid)
            .map(new_adv_node_by_id)
            .collect();

        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeUid).map(new_node_by_id).collect(),
            observer: new_node_by_id(NodeUid(good_num + adv_num)).1,
            adversary: adversary(adv_nodes.clone()),
            pk_set: pk_set.clone(),
            adv_nodes,
        };

        // inform the adversary over their nodes
        network.adversary.init(&network.adv_nodes);

        let msgs = network.adversary.step();
        for MessageWithSender { sender, tm } in msgs {
            network.dispatch_messages(sender, vec![tm]);
        }
        let mut initial_msgs: Vec<(D::NodeUid, Vec<_>)> = Vec::new();
        for (id, node) in &mut network.nodes {
            initial_msgs.push((*id, node.algo.message_iter().collect()));
        }
        for (id, msgs) in initial_msgs {
            network.dispatch_messages(id, msgs);
        }
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, sender_id: NodeUid, msgs: Q)
    where
        Q: IntoIterator<Item = TargetedMessage<D::Message, NodeUid>> + Debug,
    {
        for msg in msgs {
            match msg.target {
                Target::All => {
                    for node in self.nodes.values_mut() {
                        if node.id != sender_id {
                            node.queue.push_back((sender_id, msg.message.clone()))
                        }
                    }
                    self.observer
                        .queue
                        .push_back((sender_id, msg.message.clone()));
                    self.adversary.push_message(sender_id, msg);
                }
                Target::Node(to_id) => {
                    if self.adv_nodes.contains_key(&to_id) {
                        self.adversary.push_message(sender_id, msg);
                    } else if let Some(node) = self.nodes.get_mut(&to_id) {
                        node.queue.push_back((sender_id, msg.message));
                    } else {
                        warn!(
                            "Unknown recipient {:?} for message: {:?}",
                            to_id, msg.message
                        );
                    }
                }
            }
        }
        while !self.observer.queue.is_empty() {
            self.observer.handle_message();
        }
    }

    /// Performs one iteration of the network, consisting of the following steps:
    ///
    /// 1. Give the adversary a chance to send messages of his choosing through `Adversary::step()`
    /// 2. Let the adversary pick a node that receives its next message through
    ///    `Adversary::pick_node()`
    ///
    /// Returns the node id of the node that made progress
    pub fn step(&mut self) -> NodeUid {
        // we let the adversary send out messages to any number of nodes
        let msgs = self.adversary.step();
        for MessageWithSender { sender, tm } in msgs {
            self.dispatch_messages(sender, Some(tm));
        }

        // now one node is chosen to make progress. we let the adversary decide which node
        let id = self.adversary.pick_node(&self.nodes);

        // the node handles the incoming message and creates new outgoing ones to be dispatched
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&id).unwrap();

            // ensure the adversary is playing fair by selecting a node that will result in actual
            // progress being made. otherwise `TestNode::handle_message()` will panic on `expect()`
            // with a much more cryptic error message
            assert!(
                !node.is_idle(),
                "adversary illegally selected an idle node in pick_node()"
            );

            node.handle_message();
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(id, msgs);

        id
    }

    /// Inputs a value in node `id`.
    pub fn input(&mut self, id: NodeUid, value: D::Input) {
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&id).expect("input instance");
            node.input(value);
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(id, msgs);
    }

    /// Inputs a value in all nodes.
    #[allow(unused)] // Not used in all tests.
    pub fn input_all(&mut self, value: D::Input)
    where
        D::Input: Clone,
    {
        let ids: Vec<D::NodeUid> = self.nodes.keys().cloned().collect();
        for id in ids {
            self.input(id, value.clone());
        }
    }
}
