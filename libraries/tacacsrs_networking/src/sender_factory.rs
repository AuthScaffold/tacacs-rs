use crate::sender::traits::MessageSenderTrait;
// use crate::sender::message_sender::AsyncSessionBasedMessageSender;

pub fn get_sender() -> Box<dyn MessageSenderTrait> {
    unimplemented!()
    //Box::new(AsyncSessionBasedMessageSender {})
}

