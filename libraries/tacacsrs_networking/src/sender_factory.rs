use crate::sender::traits::MessageSenderTrait;
use crate::sender::message_sender::AsyncSessionBasedMessageSender;

pub fn get_sender() -> Box<dyn MessageSenderTrait> {
    Box::new(AsyncSessionBasedMessageSender {})
}

