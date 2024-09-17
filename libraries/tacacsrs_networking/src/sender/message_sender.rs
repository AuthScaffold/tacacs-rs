use async_trait::async_trait;
use crate::sender::traits::MessageSenderTrait;
use tacacsrs_messages::traits::TacacsBodyTrait;

pub struct AsyncSessionBasedMessageSender
{
}

#[async_trait]
impl MessageSenderTrait for AsyncSessionBasedMessageSender
{
    async fn send(&self, _request : &dyn TacacsBodyTrait) -> anyhow::Result<Box<dyn TacacsBodyTrait>>
    {
        unimplemented!("Implement me!")
    }
}