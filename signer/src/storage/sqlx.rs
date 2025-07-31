//! This module contains implementations of structs that make reading from
//! and writing from postgres easy.

use std::ops::Deref;
use std::str::FromStr as _;

use bitcoin::hashes::Hash as _;
use libp2p::Multiaddr;
use libp2p::PeerId;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::PgArgumentBuffer;
use sqlx::postgres::PgTypeInfo;
use sqlx::postgres::types::Oid;
use time::OffsetDateTime;
use time::macros::datetime;

use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::SigHash;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksBlockHeight;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;
use crate::storage::model::TaprootScriptHash;

use super::model::DbMultiaddr;
use super::model::DbPeerId;
use super::model::Timestamp;

/// The PostgreSQL epoch is 2000-01-01 00:00:00 UTC
/// (https://en.wikipedia.org/wiki/Epoch_(computing)).
const POSTGRES_EPOCH_DATETIME: OffsetDateTime = datetime!(2000-01-01 00:00:00 UTC);

/// OID for PostgreSQL's TIMESTAMPTZ type.
/// https://github.com/postgres/postgres/blob/5d6eac80cdce7aa7c5f4ec74208ddc1feea9eef3/src/include/catalog/pg_type.dat#L306
const TIMESTAMPTZ_OID: Oid = Oid(1184);

// For the [`TaprootScriptHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for TaprootScriptHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(TaprootScriptHash::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for TaprootScriptHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for TaprootScriptHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.to_byte_array();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for TaprootScriptHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`ScriptPubKey`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for ScriptPubKey {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(ScriptPubKey::from_bytes(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for ScriptPubKey {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for ScriptPubKey {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.deref().to_bytes();
        <Vec<u8> as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for ScriptPubKey {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinBlockHash::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinBlockHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.as_ref();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinBlockHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinTxId::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinTxId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinTxId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.into_bytes();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinTxId {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`PublicKey`]

/// We expect the compressed public key bytes from the database
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for PublicKey {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 33] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(PublicKey::from_slice(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for PublicKey {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 33] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// We write the compressed public key bytes to the database
impl<'r> sqlx::Encode<'r, sqlx::Postgres> for PublicKey {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.serialize();
        <[u8; 33] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for PublicKey {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 33] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`PublicKeyXOnly`]

/// We expect the compressed public key bytes from the database
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for PublicKeyXOnly {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(PublicKeyXOnly::from_slice(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for PublicKeyXOnly {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// We write the compressed public key bytes to the database
impl<'r> sqlx::Encode<'r, sqlx::Postgres> for PublicKeyXOnly {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.serialize();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for PublicKeyXOnly {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksBlockHeight`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksBlockHeight {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let height = <i64 as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        StacksBlockHeight::try_from(height).map_err(BoxDynError::from)
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksBlockHeight {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksBlockHeight {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let as_i64 = i64::try_from(*self)?;
        <i64 as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&as_i64, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksBlockHeight {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <i64 as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinBlockHeight`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinBlockHeight {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let height = <i64 as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        BitcoinBlockHeight::try_from(height).map_err(BoxDynError::from)
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinBlockHeight {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinBlockHeight {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let as_i64 = i64::try_from(*self)?;
        <i64 as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&as_i64, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinBlockHeight {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <i64 as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksBlockHash::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksBlockHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksBlockHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_bytes(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksBlockHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksPrincipal`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksPrincipal {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksPrincipal::from_str(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksPrincipal {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksPrincipal {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <String as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksPrincipal {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksTxId::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksTxId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksTxId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_bytes(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksTxId {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`SigHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SigHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(bitcoin::TapSighash::from_byte_array(bytes).into())
    }
}

impl sqlx::Type<sqlx::Postgres> for SigHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for SigHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_byte_array(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for SigHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// --- sqlx Type implementation for Timestamp --

impl sqlx::Type<sqlx::Postgres> for Timestamp {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_oid(TIMESTAMPTZ_OID)
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        // Ensure compatibility with PostgreSQL's TIMESTAMPTZ type.
        ty.oid() == Some(TIMESTAMPTZ_OID)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Timestamp {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        let duration_since_pg_epoch = **self - POSTGRES_EPOCH_DATETIME;
        let pg_epoch_micros: i64 = duration_since_pg_epoch
            .whole_microseconds()
            .try_into()
            .map_err(|_| "timestamp could not be encoded as a PostgreSQL TIMESTAMPTZ")?;

        pg_epoch_micros.encode_by_ref(buf)
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<i64>()
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Timestamp {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        // Decode the i64 representing microseconds since PostgreSQL epoch.
        let pg_epoch_micros_i64 = <i64 as sqlx::Decode<sqlx::Postgres>>::decode(value)?;

        // Create a Duration from these microseconds.
        let duration_from_pg_epoch = time::Duration::microseconds(pg_epoch_micros_i64);

        // Add this duration to the PostgreSQL epoch datetime.
        // checked_add handles potential overflow/underflow if the resulting datetime
        // is outside the representable range of OffsetDateTime.
        let datetime = POSTGRES_EPOCH_DATETIME
            .checked_add(duration_from_pg_epoch)
            .ok_or("failed to construct OffsetDateTime from decoded TIMESTAMPTZ value")?;

        Ok(datetime.into()) // Convert OffsetDateTime to Timestamp
    }
}

// --- sqlx Type implementations for DbPeerId ---

impl sqlx::Type<sqlx::Postgres> for DbPeerId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        // Stored as TEXT, so delegate to String's type info
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for DbPeerId {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        // Convert PeerId to its base58 string representation for storage
        let peer_id_str = self.to_base58();
        peer_id_str.encode_by_ref(buf)
    }

    fn size_hint(&self) -> usize {
        // Provide a reasonable estimate or delegate if possible.
        // For dynamic strings, an exact hint is hard.
        // This is often optional but can help with performance.
        self.to_base58().size_hint()
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for DbPeerId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        // Decode the TEXT from the database as a String
        let peer_id_str = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        // Parse the string back into a PeerId
        PeerId::from_str(&peer_id_str)
            .map(DbPeerId::from)
            .map_err(|e| format!("Failed to parse PeerId from database string: {e}").into())
    }
}

// --- sqlx Type implementations for DbMultiaddr ---

impl sqlx::Type<sqlx::Postgres> for DbMultiaddr {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        // Stored as TEXT, so delegate to String's type info
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for DbMultiaddr {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        // Convert Multiaddr to its string representation for storage
        let multiaddr_str = self.to_string();
        multiaddr_str.encode_by_ref(buf)
    }

    fn size_hint(&self) -> usize {
        self.to_string().size_hint()
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for DbMultiaddr {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        // Decode the TEXT from the database as a String
        let multiaddr_str = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        // Parse the string back into a Multiaddr
        Multiaddr::from_str(&multiaddr_str)
            .map(DbMultiaddr::from)
            .map_err(|e| format!("Failed to parse Multiaddr from database string: {e}").into())
    }
}
