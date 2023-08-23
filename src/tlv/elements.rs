use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub enum ElementType {
    Alphabetic,
    Alphanumeric,
    AlphanumericSpecial,
    Binary,
    DigitString, // CompressedNumeric in the EMV spec
    Numeric,
    Template,
    Dol,
}

#[derive(Copy, Clone, Debug)]
pub struct DataElement {
    pub tag: u16,
    pub name: &'static str,
    pub short_name: Option<&'static str>,
    pub typ: ElementType,
}

impl Display for DataElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DataElement {{tag: {:#04x}), name: \"{}\", short_name: {:?}, decoder: (unknown)}}",
            self.tag, self.name, self.short_name
        )
    }
}

macro_rules! elements_map {
    [$($tag:expr => $name:tt $(($short_name:tt))?: $typ:ident,)*] => {
        HashMap::from([$(
            (
                $tag,
                DataElement {
                    tag: $tag,
                    name: $name,
                    short_name: optional!($($short_name)*),
                    typ: ElementType::$typ,
                }
            )
        ,)*])
    };
}
macro_rules! optional {
    () => {None};
    ($($some:tt)*) => {Some($($some)*)};
}

lazy_static! {
    pub static ref ELEMENTS: HashMap<u16, DataElement> = elements_map![
        0x0042 => "Issuer Identification Number (IIN)": Numeric,
        0x004f => "Application Dedicated File (ADF) Name": Binary,
        0x0050 => "Application Label": AlphanumericSpecial,
        0x0057 => "Track 2 Equivalent Data": Binary,
        0x005a => "Application Primary Account Number (PAN)" ("PAN"): DigitString,
        0x0061 => "Application Template": Template,
        0x006f => "File Control Information (FCI) Template": Template,
        0x0070 => "READ RECORD Response Message Template": Template,
        0x0071 => "Issuer Script Template 1": Template,
        0x0072 => "Issuer Script Template 2": Template,
        0x0073 => "Directory Discretionary Template": Template,
        0x0077 => "Response Message Template Format 2": Template,
        0x0080 => "Response Message Template Format 1": Binary,
        0x0081 => "Amount, Authorised (Binary)": Binary,
        0x0082 => "Application Interchange Profile": Binary,
        0x0083 => "Command Template": Binary,
        0x0084 => "Dedicated File (DF) Name": Binary,
        0x0086 => "Issuer Script Command": Binary,
        0x0087 => "Application Priority Indicator": Binary,
        0x0088 => "Short File Identifier (SFI)": Binary,
        0x0089 => "Authorisation Code": Binary,
        0x008a => "Authorisation Response Code": Binary,
        0x008c => "Card Risk Management Data Object List 1 (CDOL1)": Dol,
        0x008d => "Card Risk Management Data Object List 2 (CDOL2)": Dol,
        0x008e => "Cardholder Verification Method (CVM) List": Binary,
        0x008f => "Certification Authority Public Key Index": Binary,
        0x0090 => "Issuer Public Key Certificate": Binary,
        0x0091 => "Issuer Authentication Data": Binary,
        0x0092 => "Issuer Public Key Remainder": Binary,
        0x0093 => "Signed Static Application Data": Binary,
        0x0094 => "Application File Locator (AFL)": Binary,
        0x0095 => "Terminal Verification Results": Binary,
        0x0097 => "Transaction Certificate Data Object List (TDOL)": Dol,
        0x0098 => "Transaction Certificate (TC) Hash Value": Binary,
        0x009a => "Transaction Date": Binary,
        0x009b => "Transaction Status Information": Binary,
        0x009c => "Transaction Type": Binary,
        0x009d => "Directory Definition File (DDF) Name": Binary,
        0x00a5 => "File Control Information (FCI) Proprietary Template": Template,
        0x5f20 => "Cardholder Name": AlphanumericSpecial,
        0x5f24 => "Application Expiration Date": Binary,
        0x5f25 => "Application Effective Date": Binary,
        0x5f28 => "Issuer Country Code": Binary,
        0x5f2a => "Transaction Currency Code": Numeric,
        0x5f2d => "Language Preference": Alphanumeric,
        0x5f30 => "Service Code": Binary,
        0x5f36 => "Transaction Currency Exponent": Binary,
        0x5f50 => "Issuer URL": Binary,
        0x5f53 => "International Bank Account Number (IBAN)": Binary,
        0x5f54 => "Bank Identifier Code (BIC)": Binary,
        0x5f55 => "Issuer Country Code (alpha2 format)": Alphabetic,
        0x5f56 => "Issuer Country Code (alpha3 format)": Alphabetic,
        0x5f57 => "Account Type": Binary,
        0x9f01 => "Acquirer Identifier": Binary,
        0x9f02 => "Amount, Authorised (Numeric)": Binary,
        0x9f03 => "Amount, Other (Numeric)": Binary,
        0x9f04 => "Amount, Other (Binary)": Binary,
        0x9f05 => "Application Discretionary Data": Binary,
        0x9f06 => "Application Identifier (AID) - terminal": Binary,
        0x9f07 => "Application Usage Control": Binary,
        0x9f08 => "Application Version Number": Binary,
        0x9f09 => "Application Version Number": Binary,
        0x9f0b => "Cardholder Name Extended": AlphanumericSpecial,
        0x9f0d => "Issuer Action Code - Default": Binary,
        0x9f0e => "Issuer Action Code - Denial": Binary,
        0x9f0f => "Issuer Action Code - Online": Binary,
        0x9f10 => "Issuer Application Data": Binary,
        0x9f11 => "Issuer Code Table Index": Binary,
        0x9f12 => "Application Preferred Name": AlphanumericSpecial,
        0x9f14 => "Lower Consecutive Offline Limit": Binary,
        0x9f15 => "Merchant Category Code": Binary,
        0x9f16 => "Merchant Identifier": Binary,
        0x9f17 => "Personal Identification Number (PIN) Try Counter": Binary,
        0x9f18 => "Issuer Script Identifier": Binary,
        0x9f1a => "Terminal Country Code": Binary,
        0x9f1b => "Terminal Floor Limit": Binary,
        0x9f1c => "Terminal Identification": Binary,
        0x9f1d => "Terminal Risk Management Data": Binary,
        0x9f1e => "Interface Device (IFD) Serial Number": Binary,
        0x9f1f => "Track 1 Discretionary Data": Binary,
        0x9f20 => "Track 2 Discretionary Data": Binary,
        0x9f21 => "Transaction Time": Binary,
        0x9f22 => "Certification Authority Public Key Index": Binary,
        0x9f23 => "Upper Consecutive Offline Limit": Binary,
        0x9f26 => "Application Cryptogram": Binary,
        0x9f27 => "Cryptogram Information Data": Binary,
        0x9f2d => "ICC PIN Encipherment Public Key Certificate": Binary,
        0x9f2e => "ICC PIN Encipherment Public Key Exponent": Binary,
        0x9f2f => "ICC PIN Encipherment Public Key Remainder": Binary,
        0x9f32 => "Issuer Public Key Exponent": Binary,
        0x9f33 => "Terminal Capabilities": Binary,
        0x9f34 => "Cardholder Verification Method (CVM) Results": Binary,
        0x9f35 => "Terminal Type": Binary,
        0x9f36 => "Application Transaction Counter (ATC)": Binary,
        0x9f37 => "Unpredictable Number": Binary,
        0x9f38 => "Processing Options Data Object List (PDOL)": Dol,
        0x9f39 => "Point-of-Service (POS) Entry Mode": Binary,
        0x9f3a => "Amount, Reference Currency": Binary,
        0x9f3b => "Application Reference Currency": Binary,
        0x9f3c => "Transaction Reference Currency Code": Binary,
        0x9f3d => "Transaction Reference Currency Exponent": Binary,
        0x9f40 => "Additional Terminal Capabilities": Binary,
        0x9f41 => "Transaction Sequence Counter": Binary,
        0x9f42 => "Application Currency Code": Binary,
        0x9f43 => "Application Reference Currency Exponent": Binary,
        0x9f44 => "Application Currency Exponent": Binary,
        0x9f45 => "Data Authentication Code": Binary,
        0x9f46 => "ICC Public Key Certificate": Binary,
        0x9f47 => "ICC Public Key Exponent": Binary,
        0x9f48 => "ICC Public Key Remainder": Binary,
        0x9f49 => "Dynamic Data Authentication Data Object List (DDOL)": Dol,
        0x9f4a => "Static Data Authentication Tag List": Binary,
        0x9f4b => "Signed Dynamic Application Data": Binary,
        0x9f4c => "ICC Dynamic Number": Binary,
        0x9f4d => "Log Entry": Binary,
        0x9f4e => "Merchant Name and Location": Binary,
        0x9f4f => "Log Format": Binary,
        0xbf0c => "FCI Issuer Discretionary Data": Template,
    ];
}
