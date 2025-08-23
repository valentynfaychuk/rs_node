use crate::consensus::DST_TX;
use crate::misc::blake3;
use crate::misc::bls12_381;
use crate::misc::vanilla_ser::{self, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TxAction {
    pub op: String,                       // must be "call"
    pub contract: Vec<u8>,                // can be module name like "Epoch"/"Coin" or a 48-byte BLS public key
    pub function: String,                 // function name string
    pub args: Vec<Vec<u8>>,               // list of binaries
    pub attached_symbol: Option<Vec<u8>>, // optional, 1..32 bytes
    pub attached_amount: Option<Vec<u8>>, // optional
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub signer: [u8; 48], // 48 bytes
    pub nonce: u128,      // integer
    pub actions: Vec<TxAction>,
}

#[derive(Debug, Clone)]
pub struct TxU {
    pub tx_encoded: Vec<u8>,
    pub hash: [u8; 32],      // 32 bytes
    pub signature: [u8; 96], // 96 bytes
    pub tx: Tx,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong term type: {0}")]
    WrongType(&'static str),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("invalid hash")]
    InvalidHash,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("nonce not integer")]
    NonceNotInteger,
    #[error("nonce too high")]
    NonceTooHigh,
    #[error("actions must be list")]
    ActionsNotList,
    #[error("actions length must be 1")]
    ActionsLenNot1,
    #[error("op must be call")]
    OpMustBeCall,
    #[error("contract must be binary")]
    ContractMustBeBinary,
    #[error("function must be binary")]
    FunctionMustBeBinary,
    #[error("args must be list")]
    ArgsMustBeList,
    #[error("arg must be binary")]
    ArgMustBeBinary,
    #[error("invalid contract or function")]
    InvalidContractOrFunction,
    #[error("invalid module for special meeting")]
    InvalidModuleForSpecial,
    #[error("invalid function for special meeting")]
    InvalidFunctionForSpecial,
    #[error("attached_symbol must be binary")]
    AttachedSymbolMustBeBinary,
    #[error("attached_symbol wrong size")]
    AttachedSymbolWrongSize,
    #[error("attached_amount must be binary")]
    AttachedAmountMustBeBinary,
    #[error("attached_amount must be included")]
    AttachedAmountMustBeIncluded,
    #[error("attached_symbol must be included")]
    AttachedSymbolMustBeIncluded,
    #[error(transparent)]
    VanillaSer(#[from] vanilla_ser::Error),
}

impl TxU {
    pub fn from_vanilla(tx_packed: &[u8]) -> Result<TxU, Error> {
        // decode outer map via VanillaSer
        let outer_val = vanilla_ser::decode_all(tx_packed)?;
        let outer = match &outer_val {
            Value::Map(m) => m,
            _ => return Err(Error::WrongType("outer_map")),
        };
        // helper to get a required bytes field
        let get_bytes = |m: &BTreeMap<Value, Value>, key: &'static str| -> Result<Vec<u8>, Error> {
            match m.get(&Value::Bytes(key.as_bytes().to_vec())) {
                Some(Value::Bytes(b)) => Ok(b.clone()),
                Some(_) => Err(Error::WrongType(key)),
                None => Err(Error::Missing(key)),
            }
        };
        let tx_encoded = get_bytes(outer, "tx_encoded")?;
        let hash = get_bytes(outer, "hash")?.try_into().map_err(|_| Error::WrongType("hash:32"))?;
        let signature = get_bytes(outer, "signature")?.try_into().map_err(|_| Error::WrongType("signature:96"))?;

        // decode inner tx map
        let inner_val = vanilla_ser::decode_all(&tx_encoded)?;
        let inner = match &inner_val {
            Value::Map(m) => m,
            _ => return Err(Error::WrongType("tx_map")),
        };

        let signer = get_bytes(inner, "signer")?.try_into().map_err(|_| Error::WrongType("signer:48"))?;
        let nonce = match inner.get(&Value::Bytes(b"nonce".to_vec())) {
            Some(Value::Int(i)) => u128::try_from(*i).map_err(|_| Error::NonceNotInteger)?,
            Some(_) => return Err(Error::NonceNotInteger),
            None => return Err(Error::Missing("nonce")),
        };

        let actions_val = match inner.get(&Value::Bytes(b"actions".to_vec())) {
            Some(v) => v,
            None => return Err(Error::Missing("actions")),
        };
        let actions_list = match actions_val {
            Value::List(list) => list,
            _ => return Err(Error::ActionsNotList),
        };

        let mut actions: Vec<TxAction> = Vec::with_capacity(actions_list.len());
        for a_val in actions_list {
            let amap = match a_val {
                Value::Map(m) => m,
                _ => return Err(Error::WrongType("action_map")),
            };
            let op_bytes = get_bytes(amap, "op")?;
            let op = String::from_utf8(op_bytes).map_err(|_| Error::WrongType("op_string"))?;
            let contract = get_bytes(amap, "contract")?;
            let function_bytes = get_bytes(amap, "function")?;
            let function = String::from_utf8(function_bytes).map_err(|_| Error::WrongType("function_string"))?;

            let args_v = amap.get(&Value::Bytes(b"args".to_vec())).ok_or(Error::Missing("args"))?;
            let args_l = match args_v {
                Value::List(l) => l,
                _ => return Err(Error::ArgsMustBeList),
            };
            let mut args: Vec<Vec<u8>> = Vec::with_capacity(args_l.len());
            for t in args_l {
                match t {
                    Value::Bytes(b) => args.push(b.clone()),
                    _ => return Err(Error::ArgMustBeBinary),
                }
            }

            let attached_symbol = match amap.get(&Value::Bytes(b"attached_symbol".to_vec())) {
                Some(Value::Bytes(b)) => Some(b.clone()),
                Some(_) => return Err(Error::AttachedSymbolMustBeBinary),
                None => None,
            };
            let attached_amount = match amap.get(&Value::Bytes(b"attached_amount".to_vec())) {
                Some(Value::Bytes(b)) => Some(b.clone()),
                Some(_) => return Err(Error::AttachedAmountMustBeBinary),
                None => None,
            };

            actions.push(TxAction { op, contract, function, args, attached_symbol, attached_amount });
        }

        let tx = Tx { signer, nonce, actions };
        Ok(TxU { tx_encoded, hash, signature, tx })
    }
}

fn is_ascii_eq(bytes: &[u8], s: &str) -> bool {
    std::str::from_utf8(bytes).map(|v| v == s).unwrap_or(false)
}

pub fn valid_pk(pk: &[u8]) -> bool {
    // accept burn address or any valid BLS public key
    if pk.len() == 48
        && let Ok(arr) = <&[u8; 48]>::try_from(pk)
        && arr == &crate::bic::coin::burn_address()
    {
        return true;
    }
    bls12_381::validate_public_key(pk).is_ok()
}

pub fn known_receivers(txu: &TxU) -> Vec<Vec<u8>> {
    if txu.tx.actions.is_empty() {
        return vec![];
    }
    let a = &txu.tx.actions[0];
    let c_is_coin = is_ascii_eq(&a.contract, "Coin");
    let f_is_transfer = a.function == "transfer";

    if c_is_coin && f_is_transfer {
        // cases:
        // [receiver, _amount]
        // ["AMA", receiver, _amount]
        // [receiver, _amount, _symbol]
        match a.args.as_slice() {
            [receiver, _amount] => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            [ama, receiver, _amount] if is_ascii_eq(ama, "AMA") => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            [receiver, _amount, _symbol] => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            _ => {}
        }
    }

    if is_ascii_eq(&a.contract, "Epoch") && a.function == "slash_trainer" && a.args.len() >= 2 {
        let malicious_pk = &a.args[1];
        if valid_pk(malicious_pk) {
            return vec![malicious_pk.clone()];
        }
    }

    vec![]
}

pub fn validate_basic(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    let txu = TxU::from_vanilla(tx_packed)?;

    // compute canonical hash of tx_encoded
    let h = blake3::hash(&txu.tx_encoded);
    if txu.hash.as_slice() != h.as_ref() {
        return Err(Error::InvalidHash);
    }

    // verify signature over hash with DST_TX
    bls12_381::verify(&txu.tx.signer, &txu.signature, &h, DST_TX).map_err(|_| Error::InvalidSignature)?;

    // nonce checks skipped as nonce is i64 already

    // actions checks
    if txu.tx.actions.is_empty() {
        return Err(Error::ActionsNotList);
    }
    if txu.tx.actions.len() != 1 {
        return Err(Error::ActionsLenNot1);
    }
    let a = &txu.tx.actions[0];

    if a.op != "call" {
        return Err(Error::OpMustBeCall);
    }
    if a.contract.is_empty() {
        return Err(Error::ContractMustBeBinary);
    }
    if a.function.is_empty() {
        return Err(Error::FunctionMustBeBinary);
    }

    // args already validated as binaries during unpack

    // contract/function validity
    let allowed_contract =
        is_ascii_eq(&a.contract, "Epoch") || is_ascii_eq(&a.contract, "Coin") || is_ascii_eq(&a.contract, "Contract");
    let allowed_function = a.function == "submit_sol"
        || a.function == "transfer"
        || a.function == "set_emission_address"
        || a.function == "slash_trainer"
        || a.function == "deploy";

    let valid_contract_fn =
        if allowed_contract { allowed_function } else { bls12_381::validate_public_key(&a.contract).is_ok() };
    if !valid_contract_fn {
        return Err(Error::InvalidContractOrFunction);
    }

    if is_special_meeting_block {
        if !is_ascii_eq(&a.contract, "Epoch") {
            return Err(Error::InvalidModuleForSpecial);
        }
        if a.function != "slash_trainer" {
            return Err(Error::InvalidFunctionForSpecial);
        }
    }

    // attachments
    if let Some(sym) = &a.attached_symbol {
        // must be binary and 1..32
        if sym.is_empty() || sym.len() > 32 {
            return Err(Error::AttachedSymbolWrongSize);
        }
        if a.attached_amount.is_none() {
            return Err(Error::AttachedAmountMustBeIncluded);
        }
    }
    if a.attached_amount.is_some() && a.attached_symbol.is_none() {
        return Err(Error::AttachedSymbolMustBeIncluded);
    }

    Ok(txu)
}

/// Validate wrapper delegating to validate_basic
pub fn validate(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    validate_basic(tx_packed, is_special_meeting_block)
}

/// Pack a parsed TxU back into a binary (ETF). TODO: requires VanillaSer-compatible encoder.
pub fn pack(_txu: &TxU) -> Vec<u8> {
    unimplemented!("TODO: pack using ETF/VanillaSer-compatible encoder");
}

/// Build and sign a transaction like Elixir TX.build/7. TODO: needs VanillaSer and BLS signing.
pub fn build(
    sk: &[u8],
    contract: &[u8],
    function: &str,
    args: &[Vec<u8>],
    nonce: Option<i64>,
    attached_symbol: Option<&[u8]>,
    attached_amount: Option<&[u8]>,
) -> Vec<u8> {
    // derive signer public key from secret key
    let signer_pk = crate::misc::bls12_381::get_public_key(sk).expect("invalid secret key");

    // choose nonce: Elixir uses :os.system_time(:nanosecond)
    let nonce_val: i128 = match nonce {
        Some(n) => n as i128,
        None => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            now.as_nanos() as i128
        }
    };

    // Build action map
    let mut action_map = BTreeMap::new();
    action_map.insert(Value::Bytes(b"op".to_vec()), Value::Bytes(b"call".to_vec()));
    action_map.insert(Value::Bytes(b"contract".to_vec()), Value::Bytes(contract.to_vec()));
    action_map.insert(Value::Bytes(b"function".to_vec()), Value::Bytes(function.as_bytes().to_vec()));
    let args_list = Value::List(args.iter().map(|a| Value::Bytes(a.clone())).collect());
    action_map.insert(Value::Bytes(b"args".to_vec()), args_list);
    if let (Some(sym), Some(amt)) = (attached_symbol, attached_amount) {
        action_map.insert(Value::Bytes(b"attached_symbol".to_vec()), Value::Bytes(sym.to_vec()));
        action_map.insert(Value::Bytes(b"attached_amount".to_vec()), Value::Bytes(amt.to_vec()));
    }

    // Build inner tx map
    let mut tx_map = BTreeMap::new();
    tx_map.insert(Value::Bytes(b"signer".to_vec()), Value::Bytes(signer_pk.to_vec()));
    tx_map.insert(Value::Bytes(b"nonce".to_vec()), Value::Int(nonce_val));
    tx_map.insert(Value::Bytes(b"actions".to_vec()), Value::List(vec![Value::Map(action_map)]));

    let tx_encoded = vanilla_ser::encode(&Value::Map(tx_map));
    let hash = crate::misc::blake3::hash(&tx_encoded);

    // Sign hash with DST_TX
    let signature = crate::misc::bls12_381::sign(sk, &hash, DST_TX).expect("failed to sign tx");

    // Build outer map
    let mut outer_map = BTreeMap::new();
    outer_map.insert(Value::Bytes(b"tx_encoded".to_vec()), Value::Bytes(tx_encoded));
    outer_map.insert(Value::Bytes(b"hash".to_vec()), Value::Bytes(hash.to_vec()));
    outer_map.insert(Value::Bytes(b"signature".to_vec()), Value::Bytes(signature.to_vec()));

    vanilla_ser::encode(&Value::Map(outer_map))
}

/// Chain-level validity checks (nonce, balance, epoch). TODO: requires Consensus state.
pub fn chain_valid(txu: &TxU) -> bool {
    // elixir logic:
    // chainNonce = Consensus.chain_nonce(txu.tx.signer)
    // nonceValid = !chainNonce or txu.tx.nonce > chainNonce
    let chain_nonce = crate::consensus::chain_nonce(&txu.tx.signer);
    let nonce_valid = match chain_nonce {
        None => true,
        Some(n) => txu.tx.nonce > n,
    };

    // hasBalance = BIC.Base.exec_cost(txu) <= Consensus.chain_balance(txu.tx.signer)
    let has_balance = crate::bic::base::exec_cost(txu) <= crate::consensus::chain_balance(&txu.tx.signer);

    // hasSol / epochSolValid
    let mut epoch_sol_valid = true;
    if let Some(action) = txu.tx.actions.first()
        && action.function == "submit_sol"
        && let Some(first_arg) = action.args.first()
        && first_arg.len() >= 4
    {
        let sol_epoch = u32::from_le_bytes([first_arg[0], first_arg[1], first_arg[2], first_arg[3]]);
        epoch_sol_valid = crate::consensus::chain_epoch() as u32 == sol_epoch;
    }

    epoch_sol_valid && nonce_valid && has_balance
}
