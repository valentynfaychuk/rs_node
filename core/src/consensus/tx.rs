use crate::bls::{self, DST_TX};
use crate::proto_enc::{
    ParseError, TermExt, map_term_to_map, to_binary_required, to_list_required, to_string_required,
};
use blake3;
use eetf::{Atom, Term};

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
    pub signer: Vec<u8>, // 48 bytes
    pub nonce: i64,      // integer
    pub actions: Vec<TxAction>,
}

#[derive(Debug, Clone)]
pub struct TxU {
    pub tx_encoded: Vec<u8>,
    pub hash: Vec<u8>,      // 32 bytes
    pub signature: Vec<u8>, // 96 bytes
    pub tx: Tx,
}

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("etf decode error")]
    Decode,
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
}

impl From<ParseError> for TxError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::Decode(_) => Self::Decode,
            ParseError::Missing(f) => Self::Missing(f),
            ParseError::WrongType(t) => Self::WrongType(t),
            _ => Self::Decode,
        }
    }
}

pub fn unpack_etf(tx_packed: &[u8]) -> Result<TxU, TxError> {
    // Outer: %{tx_encoded: bin, hash: bin, signature: bin}
    let outer_term = Term::decode(tx_packed).map_err(|_| TxError::Decode)?;
    let outer = map_term_to_map(&outer_term)?;

    let tx_encoded = to_binary_required(
        outer.get(&Term::Atom(Atom::from("tx_encoded"))).ok_or(TxError::Missing("tx_encoded"))?,
        "tx_encoded",
    )?;
    let hash = to_binary_required(outer.get(&Term::Atom(Atom::from("hash"))).ok_or(TxError::Missing("hash"))?, "hash")?;
    let signature = to_binary_required(
        outer.get(&Term::Atom(Atom::from("signature"))).ok_or(TxError::Missing("signature"))?,
        "signature",
    )?;

    // Inner tx: %{signer: pk, nonce: int, actions: [ ... ]}
    let inner_term = Term::decode(&tx_encoded[..]).map_err(|_| TxError::Decode)?;
    let inner = map_term_to_map(&inner_term)?;

    let signer =
        to_binary_required(inner.get(&Term::Atom(Atom::from("signer"))).ok_or(TxError::Missing("signer"))?, "signer")?;
    let nonce_term = inner.get(&Term::Atom(Atom::from("nonce"))).ok_or(TxError::Missing("nonce"))?;
    let nonce = nonce_term.integer().ok_or(TxError::NonceNotInteger)?;

    let actions_term = inner.get(&Term::Atom(Atom::from("actions"))).ok_or(TxError::Missing("actions"))?;
    let actions_list = to_list_required(actions_term, "actions")?;

    let mut actions = Vec::with_capacity(actions_list.len());
    for a in actions_list {
        let m = map_term_to_map(a)?;

        let op = to_string_required(m.get(&Term::Atom(Atom::from("op"))).ok_or(TxError::Missing("op"))?, "op")?;
        let contract = to_binary_required(
            m.get(&Term::Atom(Atom::from("contract"))).ok_or(TxError::Missing("contract"))?,
            "contract",
        )?;
        let function = to_string_required(
            m.get(&Term::Atom(Atom::from("function"))).ok_or(TxError::Missing("function"))?,
            "function",
        )?;

        let args_t = m.get(&Term::Atom(Atom::from("args"))).ok_or(TxError::Missing("args"))?;
        let args_list = to_list_required(args_t, "args")?;
        let mut args = Vec::with_capacity(args_list.len());
        for t in args_list {
            let b = t.binary().ok_or(TxError::ArgMustBeBinary)?;
            args.push(b.to_vec());
        }

        let attached_symbol =
            m.get(&Term::Atom(Atom::from("attached_symbol"))).and_then(|t| t.binary()).map(|b| b.to_vec());
        let attached_amount =
            m.get(&Term::Atom(Atom::from("attached_amount"))).and_then(|t| t.binary()).map(|b| b.to_vec());

        actions.push(TxAction { op, contract, function, args, attached_symbol, attached_amount });
    }

    let tx = Tx { signer, nonce, actions };
    Ok(TxU { tx_encoded, hash, signature, tx })
}

fn is_ascii_eq(bytes: &[u8], s: &str) -> bool {
    std::str::from_utf8(bytes).map(|v| v == s).unwrap_or(false)
}

pub fn valid_pk(pk: &[u8]) -> bool {
    // Accept burn address or any valid BLS public key, like Elixir TX.valid_pk/1
    if pk.len() == 48 {
        if let Ok(arr) = <&[u8; 48]>::try_from(pk) {
            if arr == &crate::bic::coin::burn_address() {
                return true;
            }
        }
    }
    bls::validate_public_key(pk).is_ok()
}

pub fn known_receivers(txu: &TxU) -> Vec<Vec<u8>> {
    if txu.tx.actions.is_empty() {
        return vec![];
    }
    let a = &txu.tx.actions[0];
    let c_is_coin = is_ascii_eq(&a.contract, "Coin");
    let f_is_transfer = a.function == "transfer";

    if c_is_coin && f_is_transfer {
        // Cases:
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

    if is_ascii_eq(&a.contract, "Epoch") && a.function == "slash_trainer" {
        if a.args.len() >= 2 {
            let malicious_pk = &a.args[1];
            if valid_pk(malicious_pk) {
                return vec![malicious_pk.clone()];
            }
        }
    }

    vec![]
}

pub fn validate_basic(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, TxError> {
    let txu = unpack_etf(tx_packed)?;

    // Compute canonical hash of tx_encoded
    let h = blake3::hash(&txu.tx_encoded);
    if txu.hash.as_slice() != h.as_bytes() {
        return Err(TxError::InvalidHash);
    }

    // Verify signature over hash with DST_TX
    bls::verify(&txu.tx.signer, &txu.signature, h.as_bytes(), DST_TX).map_err(|_| TxError::InvalidSignature)?;

    // Nonce checks (Elixir allowed up to 99..(20 digits); here we skip as nonce is i64 already)

    // Actions checks
    if txu.tx.actions.is_empty() {
        return Err(TxError::ActionsNotList);
    }
    if txu.tx.actions.len() != 1 {
        return Err(TxError::ActionsLenNot1);
    }
    let a = &txu.tx.actions[0];

    if a.op != "call" {
        return Err(TxError::OpMustBeCall);
    }
    if a.contract.is_empty() {
        return Err(TxError::ContractMustBeBinary);
    }
    if a.function.is_empty() {
        return Err(TxError::FunctionMustBeBinary);
    }

    // Args already validated as binaries during unpack

    // Contract/function validity
    let allowed_contract =
        is_ascii_eq(&a.contract, "Epoch") || is_ascii_eq(&a.contract, "Coin") || is_ascii_eq(&a.contract, "Contract");
    let allowed_function = a.function == "submit_sol"
        || a.function == "transfer"
        || a.function == "set_emission_address"
        || a.function == "slash_trainer"
        || a.function == "deploy";

    let valid_contract_fn =
        if allowed_contract { allowed_function } else { bls::validate_public_key(&a.contract).is_ok() };
    if !valid_contract_fn {
        return Err(TxError::InvalidContractOrFunction);
    }

    if is_special_meeting_block {
        if !is_ascii_eq(&a.contract, "Epoch") {
            return Err(TxError::InvalidModuleForSpecial);
        }
        if a.function != "slash_trainer" {
            return Err(TxError::InvalidFunctionForSpecial);
        }
    }

    // Attachments
    if let Some(sym) = &a.attached_symbol {
        // must be binary and 1..32
        if sym.is_empty() || sym.len() > 32 {
            return Err(TxError::AttachedSymbolWrongSize);
        }
        if a.attached_amount.is_none() {
            return Err(TxError::AttachedAmountMustBeIncluded);
        }
    }
    if a.attached_amount.is_some() && a.attached_symbol.is_none() {
        return Err(TxError::AttachedSymbolMustBeIncluded);
    }

    Ok(txu)
}

// --- Cross-dependency API alignment with Elixir TX module ---
/// Validate wrapper mirroring Elixir TX.validate/2, delegating to validate_basic.
pub fn validate(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, TxError> {
    validate_basic(tx_packed, is_special_meeting_block)
}

/// Pack a parsed TxU back into a binary (ETF). TODO: requires VanillaSer-compatible encoder.
pub fn pack(_txu: &TxU) -> Vec<u8> {
    unimplemented!("TODO: pack using ETF/VanillaSer-compatible encoder");
}

/// Build and sign a transaction like Elixir TX.build/7. TODO: needs VanillaSer and BLS signing.
pub fn build(
    _sk: &[u8],
    _contract: &[u8],
    _function: &str,
    _args: &[Vec<u8>],
    _nonce: Option<i64>,
    _attached_symbol: Option<&[u8]>,
    _attached_amount: Option<&[u8]>,
) -> Vec<u8> {
    unimplemented!("TODO: build and sign tx packed as ETF");
}

/// Chain-level validity checks (nonce, balance, epoch). TODO: requires Consensus state.
pub fn chain_valid(txu: &TxU) -> bool {
    // Elixir logic:
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
    if let Some(action) = txu.tx.actions.first() {
        if action.function == "submit_sol" {
            if let Some(first_arg) = action.args.get(0) {
                if first_arg.len() >= 4 {
                    let sol_epoch = u32::from_le_bytes([first_arg[0], first_arg[1], first_arg[2], first_arg[3]]);
                    epoch_sol_valid = crate::consensus::chain_epoch() as u32 == sol_epoch;
                }
            }
        }
    }

    epoch_sol_valid && nonce_valid && has_balance
}
