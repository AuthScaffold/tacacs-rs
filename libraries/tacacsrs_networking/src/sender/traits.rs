use async_trait::async_trait;
use tacacsrs_messages::traits::TacacsBodyTrait;

#[async_trait]
pub trait MessageSenderTrait {
    async fn send(&self, request : &dyn TacacsBodyTrait) -> anyhow::Result<Box<dyn TacacsBodyTrait>>;
}
