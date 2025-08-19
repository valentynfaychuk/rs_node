use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, List, Term};
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::path::Path;

/// Produce a hex dump similar to `hexdump -C` for a binary slice.
pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let address = i * 16;
        // 8-digit upper-case hex address
        let offset_str = format!("{address:08X}");

        // hex bytes (2 hex chars per byte + 1 space => up to 48 chars)
        let mut hex_bytes = String::new();
        for b in chunk {
            hex_bytes.push_str(&format!("{:02X} ", b));
        }
        // pad to 48 characters to align ASCII column
        while hex_bytes.len() < 48 {
            hex_bytes.push(' ');
        }

        // ASCII representation (32..=126 printable)
        let ascii: String = chunk.iter().map(|&b| if (32..=126).contains(&b) { b as char } else { '.' }).collect();

        out.push_str(&format!("{offset_str}  {hex_bytes}  {ascii}\n"));
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Safely quote a string for simple bash usage. Removes single quotes and wraps in single quotes.
pub fn sbash(term: &str) -> String {
    let mut s = term.replace('\'', "");
    if s.is_empty() {
        String::new()
    } else {
        s.insert(0, '\'');
        s.push('\'');
        s
    }
}

/// Keep only ASCII characters considered printable for our use-case.
pub fn ascii(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            let code = c as u32;
            code == 32
                || (123..=126).contains(&code)
                || (('!' as u32)..=('@' as u32)).contains(&code)
                || (('[' as u32)..=('_' as u32)).contains(&code)
                || (('0' as u32)..=('9' as u32)).contains(&code)
                || (('A' as u32)..=('Z' as u32)).contains(&code)
                || (('a' as u32)..=('z' as u32)).contains(&code)
        })
        .collect()
}

pub fn is_ascii_clean(input: &str) -> bool {
    ascii(input) == input
}

pub fn alphanumeric(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

pub fn is_alphanumeric(input: &str) -> bool {
    alphanumeric(input) == input
}

/// Keep ASCII letters, digits, '_' and '-'
pub fn ascii_dash_underscore(input: &str) -> String {
    input.chars().filter(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-').collect()
}

/// Hostname-friendly subset: lowercase letters, digits, and '-'
pub fn alphanumeric_hostname(input: &str) -> String {
    input.chars().filter(|&c| matches!(c, 'a'..='z' | '0'..='9' | '-')).collect()
}

/// Safe extension: returns ".ext" where ext is alphanumeric-only, derived from the given path
pub fn sext(path: &str) -> String {
    let ext = Path::new(path).extension().and_then(|os| os.to_str()).map(|s| alphanumeric(s)).unwrap_or_default();
    format!(".{}", ext)
}

/// Trim trailing slash from url
pub fn url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Trim trailing slash on base and append path verbatim
pub fn url_with(url: &str, path: &str) -> String {
    format!("{}{}", url, path)
}

/// Convert http(s) to ws(s) and append path
pub fn url_to_ws(url: &str, path: &str) -> String {
    let u = url_with(url, path);
    if let Some(rest) = u.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = u.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else {
        u
    }
}

/// Lightweight helpers so you can keep calling `.atom()`, `.integer()`, etc.
pub trait TermExt {
    fn as_atom(&self) -> Option<&Atom>;
    fn get_integer(&self) -> Option<i64>;
    fn get_binary(&self) -> Option<&[u8]>;
    fn get_list(&self) -> Option<&[Term]>;
    fn get_string(&self) -> Option<String>;
    fn get_map(&self) -> Option<HashMap<Term, Term>>;
}

impl TermExt for Term {
    fn as_atom(&self) -> Option<&Atom> {
        TryAsRef::<Atom>::try_as_ref(self)
    }

    fn get_integer(&self) -> Option<i64> {
        match self {
            Term::FixInteger(i) => Some(i.value as i64),
            Term::BigInteger(bi) => bi.value.to_i64(),
            _ => None,
        }
    }

    fn get_binary(&self) -> Option<&[u8]> {
        TryAsRef::<Binary>::try_as_ref(self).map(|b| b.bytes.as_slice())
    }

    fn get_list(&self) -> Option<&[Term]> {
        TryAsRef::<List>::try_as_ref(self).map(|l| l.elements.as_slice())
    }

    fn get_string(&self) -> Option<String> {
        // Erlang strings come across either as ByteList or Binary
        if let Term::ByteList(bl) = self {
            std::str::from_utf8(&bl.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Binary(b) = self {
            std::str::from_utf8(&b.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Atom(a) = self {
            Some(a.name.clone())
        } else {
            None
        }
    }

    fn get_map(&self) -> Option<HashMap<Term, Term>> {
        match self {
            Term::Map(m) => Some(m.map.clone()),
            _ => None,
        }
    }
}

pub fn get_map_field<'a>(map: &'a HashMap<Term, Term>, key: &str) -> Option<&'a Term> {
    map.get(&Term::Atom(Atom::from(key)))
}

// defmodule Util do
// def hexdump(binary) when is_binary(binary) do
// :binary.bin_to_list(binary)
// |> Enum.chunk_every(16, 16, [])
// |> Enum.with_index()
// |> Enum.map(fn {chunk, index} ->
// # Calculate the offset in bytes
// address = index * 16
//
// # Convert offset to hex, zero-padded to 8 characters
// offset_str = address
// |> Integer.to_string(16)
// |> String.upcase()
// |> String.pad_leading(8, "0")
//
// # Convert each byte in the chunk to 2-digit hex (upper-case)
// hex_bytes = chunk
// |> Enum.map(fn byte ->
//                     byte
// |> Integer.to_string(16)
// |> String.upcase()
// |> String.pad_leading(2, "0")
// end)
// |> Enum.join(" ")
//
// # Pad the hex field so the ASCII section is always aligned
// # Each byte takes up 2 hex chars + 1 space = 3 chars
// # For 16 bytes, that's 16 * 3 = 48 chars total.
// # If we have fewer than 16 bytes in this chunk, add enough spaces to reach 48.
// needed_spaces = 48 - String.length(hex_bytes)
// hex_bytes_padded = hex_bytes <> String.duplicate(" ", needed_spaces)
//
// # Convert to ASCII, replacing non-printable characters with "."
// ascii = chunk
// |> Enum.map(fn byte ->
// if byte in 32..126 do <<byte>> else "." end
// end)
// |> Enum.join()
//
// # Build the final line
// "#{offset_str}  #{hex_bytes_padded}  #{ascii}"
// end)
// |> Enum.join("\n")
// end
//
// def sbash(term) do
// term = "#{term}"
// term = String.replace(term, "'", "")
// if term == "" do "" else "'#{term}'" end
// end
//
// def ascii(string) do
// for <<c <- string>>,
// c == 32
// or c in 123..126
// or c in ?!..?@
// or c in ?[..?_
// or c in ?0..?9
// or c in ?A..?Z
// or c in ?a..?z,
// into: "" do
// <<c>>
// end
// end
// def ascii?(string) do
// string == ascii(string)
// end
//
// def alphanumeric(string) do
// for <<c <- string>>,
// c in ?0..?9
// or c in ?A..?Z
// or c in ?a..?z,
// into: "" do
// <<c>>
// end
// end
// def alphanumeric?(string) do
// string == alphanumeric(string)
// end
//
// def ascii_dash_underscore(string) do
// string
// |> String.to_charlist()
// |> Enum.filter(fn(char)->
// char in 97..122
// || char in 65..90
// || char in 48..57
// || char in [95, 45] #"_-"
// end)
// |> List.to_string()
// end
//
// def alphanumeric_hostname(string) do
// string
// |> String.to_charlist()
// |> Enum.filter(fn(char)->
// char in 97..122
// || char in 48..57
// || char in [45] #"-"
// end)
// |> List.to_string()
// end
//
// def sext(path) do
// ext = Path.extname(path)
// |> alphanumeric()
// "." <> ext
// end
//
// def url(url) do
// String.trim(url, "/")
// end
//
// def url(url, path) do
// String.trim(url, "/") <> path
// end
//
// def url_to_ws(url, path) do
// url = String.trim(url, "/") <> path
// url = String.replace(url, "https://", "wss://")
// url = String.replace(url, "http://", "ws://")
// end
//
// def get(url, headers \\ %{}, opts \\ %{}) do
// %{host: host} = URI.parse(url)
// ssl_opts = [
// {:server_name_indication, '#{host}'},
// {:verify,:verify_peer},
// {:depth,99},
// {:cacerts, :certifi.cacerts()},
// #{:verify_fun, verifyFun},
// {:partial_chain, &Photon.GenTCP.partial_chain/1},
// {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
// ]
// opts = Map.merge(opts, %{ssl_options: ssl_opts})
// :comsat_http.get(url, headers, opts)
// end
//
// def get_json(url, headers \\ %{}, opts \\ %{}) do
// {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
// {:ok, %{body: body}} = get(url, headers, opts)
// #IO.inspect body
// JSX.decode!(body, [{:labels, labels}])
// end
//
// def delete(url, body, headers \\ %{}, opts \\ %{}) do
// %{host: host} = URI.parse(url)
// ssl_opts = [
// {:server_name_indication, '#{host}'},
// {:verify,:verify_peer},
// {:depth,99},
// {:cacerts, :certifi.cacerts()},
// #{:verify_fun, verifyFun},
// {:partial_chain, &Photon.GenTCP.partial_chain/1},
// {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
// ]
// opts = Map.merge(opts, %{ssl_options: ssl_opts})
// body = if !is_binary(body) do JSX.encode!(body) else body end
// :comsat_http.delete(url, headers, body, opts)
// end
//
// def delete_json(url, body, headers \\ %{}, opts \\ %{}) do
// {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
// {:ok, %{body: body}} = delete(url, body, headers, opts)
// JSX.decode!(body, [{:labels, labels}])
// end
//
// def post(url, body, headers \\ %{}, opts \\ %{}) do
// %{host: host} = URI.parse(url)
// ssl_opts = [
// {:server_name_indication, '#{host}'},
// {:verify,:verify_peer},
// {:depth,99},
// {:cacerts, :certifi.cacerts()},
// #{:verify_fun, verifyFun},
// {:partial_chain, &Photon.GenTCP.partial_chain/1},
// {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
// ]
// opts = Map.merge(opts, %{ssl_options: ssl_opts})
// body = if !is_binary(body) do JSX.encode!(body) else body end
// :comsat_http.post(url, headers, body, opts)
// end
//
// def post_json(url, body, headers \\ %{}, opts \\ %{}) do
// {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
// {:ok, %{body: body}} = post(url, body, headers, opts)
// #IO.inspect body
// JSX.decode!(body, [{:labels, labels}])
// end
//
// def put(url, body, headers \\ %{}, opts \\ %{}) do
// %{host: host} = URI.parse(url)
// ssl_opts = [
// {:server_name_indication, '#{host}'},
// {:verify,:verify_peer},
// {:depth,99},
// {:cacerts, :certifi.cacerts()},
// #{:verify_fun, verifyFun},
// {:partial_chain, &Photon.GenTCP.partial_chain/1},
// {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
// ]
// opts = Map.merge(opts, %{ssl_options: ssl_opts})
// body = if !is_binary(body) do JSX.encode!(body) else body end
// :comsat_http.put(url, headers, body, opts)
// end
//
// def put_json(url, body, headers \\ %{}, opts \\ %{}) do
// {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
// {:ok, %{body: body}} = put(url, body, headers, opts)
// JSX.decode!(body, [{:labels, labels}])
// end
//
// def b3sum(path) do
// {b3sum, 0} = System.shell("b3sum --no-names --raw #{U.b(path)}")
// Base.hex_encode32(b3sum, padding: false, case: :lower)
// end
//
// def pad_bitstring_to_bytes(bitstring) do
// bits = bit_size(bitstring)
// padding = rem(8 - rem(bits, 8), 8)
// <<bitstring::bitstring, 0::size(padding)>>
// end
//
// def set_bit(bin, i) when is_bitstring(bin) and is_integer(i) do
// n = bit_size(bin)
//
// if i < 0 or i >= n do
// raise ArgumentError, "Bit index out of range: #{i} (size is #{n})"
// end
//
// left_size = i
// << left::size(left_size), _old_bit::size(1), right::bitstring >> = bin
// << left::size(left_size), 1::size(1), right::bitstring >>
// end
//
// def get_bit(bin, i) when is_bitstring(bin) and is_integer(i) do
// n = bit_size(bin)
//
// if i < 0 or i >= n do
// raise ArgumentError, "Bit index out of range: #{i} (size is #{n})"
// end
//
// left_size = i
// # Pattern-match to extract the bit
// <<_left::size(left_size), bit::size(1), _right::bitstring>> = bin
// bit == 1
// end
//
// def index_of(list, key) do
// {result, index} = Enum.reduce_while(list, {nil, 0}, fn(element, {result, index})->
// if element == key do
// {:halt, {element, index}}
// else
// {:cont, {nil, index+1}}
// end
// end)
// if result do
// index
// end
// end
//
// def verify_time_sync() do
// {res, _} = System.shell("timedatectl status")
// String.contains?(res, "System clock synchronized: yes")
// end
// end
