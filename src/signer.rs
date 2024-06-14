use crate::*;

use async_trait::async_trait;
use crate::signature::{ObjSignature, SignatureSource};

#[async_trait]
pub trait ObjSigner: Sync + Send {
    fn public_key(&self) -> &PublicKey;
    async fn sign(&self, data: &[u8], sign_source: &SignatureSource) -> BuckyResult<ObjSignature>;
}

#[async_trait]
impl ObjSigner for Box<dyn ObjSigner> {
    fn public_key(&self) -> &PublicKey {
        self.as_ref().public_key()
    }

    async fn sign(&self, data: &[u8], sign_source: &SignatureSource) -> BuckyResult<ObjSignature> {
        self.as_ref().sign(data, sign_source).await
    }
}
