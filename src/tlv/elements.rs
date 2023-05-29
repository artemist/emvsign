use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ElementType {
    Alphabetic,
    Alphanumeric,
    AlphanumericSpecial,
    Binary,
    CompressedNumeric,
    Numeric,
    Template,
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

lazy_static! {
    pub static ref ELEMENTS: HashMap<u16, DataElement> = HashMap::from([
        (
            0x0042u16,
            DataElement {
                tag: 0x0042,
                name: "Issuer Identification Number (IIN)",
                short_name: None,
                typ: ElementType::Numeric,
            }
        ),
        (
            0x004fu16,
            DataElement {
                tag: 0x004f,
                name: "Application Dedicated File (ADF) Name",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0050u16,
            DataElement {
                tag: 0x0050,
                name: "Application Label",
                short_name: None,
                typ: ElementType::AlphanumericSpecial,
            }
        ),
        (
            0x0057u16,
            DataElement {
                tag: 0x0057,
                name: "Track 2 Equivalent Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x005au16,
            DataElement {
                tag: 0x005a,
                name: "Application Primary Account Number (PAN)",
                short_name: Some("PAN"),
                typ: ElementType::CompressedNumeric,
            }
        ),
        (
            0x0061u16,
            DataElement {
                tag: 0x0061,
                name: "Application Template",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x006fu16,
            DataElement {
                tag: 0x006f,
                name: "File Control Information (FCI) Template",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x0070u16,
            DataElement {
                tag: 0x0070,
                name: "READ RECORD Response Message Template",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x0071u16,
            DataElement {
                tag: 0x0071,
                name: "Issuer Script Template 1",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x0072u16,
            DataElement {
                tag: 0x0072,
                name: "Issuer Script Template 2",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x0073u16,
            DataElement {
                tag: 0x0073,
                name: "Directory Discretionary Template",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x0077u16,
            DataElement {
                tag: 0x0077,
                name: "Response Message Template Format 2",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0080u16,
            DataElement {
                tag: 0x0080,
                name: "Response Message Template Format 1",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0081u16,
            DataElement {
                tag: 0x0081,
                name: "Amount, Authorised (Binary)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0082u16,
            DataElement {
                tag: 0x0082,
                name: "Application Interchange Profile",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0083u16,
            DataElement {
                tag: 0x0083,
                name: "Command Template",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0084u16,
            DataElement {
                tag: 0x0084,
                name: "Dedicated File (DF) Name",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0086u16,
            DataElement {
                tag: 0x0086,
                name: "Issuer Script Command",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0087u16,
            DataElement {
                tag: 0x0087,
                name: "Application Priority Indicator",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0088u16,
            DataElement {
                tag: 0x0088,
                name: "Short File Identifier (SFI)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0089u16,
            DataElement {
                tag: 0x0089,
                name: "Authorisation Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x008au16,
            DataElement {
                tag: 0x008a,
                name: "Authorisation Response Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x008cu16,
            DataElement {
                tag: 0x008c,
                name: "Card Risk Management Data Object List 1 (CDOL1)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x008du16,
            DataElement {
                tag: 0x008d,
                name: "Card Risk Management Data Object List 2 (CDOL2)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x008eu16,
            DataElement {
                tag: 0x008e,
                name: "Cardholder Verification Method (CVM) List",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x008fu16,
            DataElement {
                tag: 0x008f,
                name: "Certification Authority Public Key Index",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0090u16,
            DataElement {
                tag: 0x0090,
                name: "Issuer Public Key Certificate",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0091u16,
            DataElement {
                tag: 0x0091,
                name: "Issuer Authentication Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0092u16,
            DataElement {
                tag: 0x0092,
                name: "Issuer Public Key Remainder",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0093u16,
            DataElement {
                tag: 0x0093,
                name: "Signed Static Application Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0094u16,
            DataElement {
                tag: 0x0094,
                name: "Application File Locator (AFL)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0095u16,
            DataElement {
                tag: 0x0095,
                name: "Terminal Verification Results",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0097u16,
            DataElement {
                tag: 0x0097,
                name: "Transaction Certificate Data Object List (TDOL)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x0098u16,
            DataElement {
                tag: 0x0098,
                name: "Transaction Certificate (TC) Hash Value",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x009au16,
            DataElement {
                tag: 0x009a,
                name: "Transaction Date",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x009bu16,
            DataElement {
                tag: 0x009b,
                name: "Transaction Status Information",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x009cu16,
            DataElement {
                tag: 0x009c,
                name: "Transaction Type",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x009du16,
            DataElement {
                tag: 0x009d,
                name: "Directory Definition File (DDF) Name",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x00a5u16,
            DataElement {
                tag: 0x00a5,
                name: "File Control Information (FCI) Proprietary Template",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
        (
            0x5f20u16,
            DataElement {
                tag: 0x5f20,
                name: "Cardholder Name",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f24u16,
            DataElement {
                tag: 0x5f24,
                name: "Application Expiration Date",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f25u16,
            DataElement {
                tag: 0x5f25,
                name: "Application Effective Date",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f28u16,
            DataElement {
                tag: 0x5f28,
                name: "Issuer Country Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f2au16,
            DataElement {
                tag: 0x5f2a,
                name: "Transaction Currency Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f2du16,
            DataElement {
                tag: 0x5f2d,
                name: "Language Preference",
                short_name: None,
                typ: ElementType::Alphanumeric,
            }
        ),
        (
            0x5f30u16,
            DataElement {
                tag: 0x5f30,
                name: "Service Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f36u16,
            DataElement {
                tag: 0x5f36,
                name: "Transaction Currency Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f50u16,
            DataElement {
                tag: 0x5f50,
                name: "Issuer URL",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f53u16,
            DataElement {
                tag: 0x5f53,
                name: "International Bank Account Number (IBAN)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f54u16,
            DataElement {
                tag: 0x5f54,
                name: "Bank Identifier Code (BIC)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x5f55u16,
            DataElement {
                tag: 0x5f55,
                name: "Issuer Country Code (alpha2 format)",
                short_name: None,
                typ: ElementType::Alphabetic,
            }
        ),
        (
            0x5f56u16,
            DataElement {
                tag: 0x5f56,
                name: "Issuer Country Code (alpha3 format)",
                short_name: None,
                typ: ElementType::Alphabetic,
            }
        ),
        (
            0x5f57u16,
            DataElement {
                tag: 0x5f57,
                name: "Account Type",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f01u16,
            DataElement {
                tag: 0x9f01,
                name: "Acquirer Identifier",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f02u16,
            DataElement {
                tag: 0x9f02,
                name: "Amount, Authorised (Numeric)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f03u16,
            DataElement {
                tag: 0x9f03,
                name: "Amount, Other (Numeric)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f04u16,
            DataElement {
                tag: 0x9f04,
                name: "Amount, Other (Binary)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f05u16,
            DataElement {
                tag: 0x9f05,
                name: "Application Discretionary Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f06u16,
            DataElement {
                tag: 0x9f06,
                name: "Application Identifier (AID) - terminal",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f07u16,
            DataElement {
                tag: 0x9f07,
                name: "Application Usage Control",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f08u16,
            DataElement {
                tag: 0x9f08,
                name: "Application Version Number",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f09u16,
            DataElement {
                tag: 0x9f09,
                name: "Application Version Number",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f0bu16,
            DataElement {
                tag: 0x9f0b,
                name: "Cardholder Name Extended",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f0du16,
            DataElement {
                tag: 0x9f0d,
                name: "Issuer Action Code - Default",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f0eu16,
            DataElement {
                tag: 0x9f0e,
                name: "Issuer Action Code - Denial",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f0fu16,
            DataElement {
                tag: 0x9f0f,
                name: "Issuer Action Code - Online",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f10u16,
            DataElement {
                tag: 0x9f10,
                name: "Issuer Application Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f11u16,
            DataElement {
                tag: 0x9f11,
                name: "Issuer Code Table Index",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f12u16,
            DataElement {
                tag: 0x9f12,
                name: "Application Preferred Name",
                short_name: None,
                typ: ElementType::AlphanumericSpecial,
            }
        ),
        (
            0x9f14u16,
            DataElement {
                tag: 0x9f14,
                name: "Lower Consecutive Offline Limit",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f15u16,
            DataElement {
                tag: 0x9f15,
                name: "Merchant Category Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f16u16,
            DataElement {
                tag: 0x9f16,
                name: "Merchant Identifier",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f17u16,
            DataElement {
                tag: 0x9f17,
                name: "Personal Identification Number (PIN) Try Counter",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f18u16,
            DataElement {
                tag: 0x9f18,
                name: "Issuer Script Identifier",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1au16,
            DataElement {
                tag: 0x9f1a,
                name: "Terminal Country Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1bu16,
            DataElement {
                tag: 0x9f1b,
                name: "Terminal Floor Limit",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1cu16,
            DataElement {
                tag: 0x9f1c,
                name: "Terminal Identification",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1du16,
            DataElement {
                tag: 0x9f1d,
                name: "Terminal Risk Management Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1eu16,
            DataElement {
                tag: 0x9f1e,
                name: "Interface Device (IFD) Serial Number",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f1fu16,
            DataElement {
                tag: 0x9f1f,
                name: "Track 1 Discretionary Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f20u16,
            DataElement {
                tag: 0x9f20,
                name: "Track 2 Discretionary Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f21u16,
            DataElement {
                tag: 0x9f21,
                name: "Transaction Time",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f22u16,
            DataElement {
                tag: 0x9f22,
                name: "Certification Authority Public Key Index",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f23u16,
            DataElement {
                tag: 0x9f23,
                name: "Upper Consecutive Offline Limit",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f26u16,
            DataElement {
                tag: 0x9f26,
                name: "Application Cryptogram",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f27u16,
            DataElement {
                tag: 0x9f27,
                name: "Cryptogram Information Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f2du16,
            DataElement {
                tag: 0x9f2d,
                name: "ICC PIN Encipherment Public Key Certificate",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f2eu16,
            DataElement {
                tag: 0x9f2e,
                name: "ICC PIN Encipherment Public Key Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f2fu16,
            DataElement {
                tag: 0x9f2f,
                name: "ICC PIN Encipherment Public Key Remainder",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f32u16,
            DataElement {
                tag: 0x9f32,
                name: "Issuer Public Key Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f33u16,
            DataElement {
                tag: 0x9f33,
                name: "Terminal Capabilities",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f34u16,
            DataElement {
                tag: 0x9f34,
                name: "Cardholder Verification Method (CVM) Results",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f35u16,
            DataElement {
                tag: 0x9f35,
                name: "Terminal Type",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f36u16,
            DataElement {
                tag: 0x9f36,
                name: "Application Transaction Counter (ATC)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f37u16,
            DataElement {
                tag: 0x9f37,
                name: "Unpredictable Number",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f38u16,
            DataElement {
                tag: 0x9f38,
                name: "Processing Options Data Object List (PDOL)",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f39u16,
            DataElement {
                tag: 0x9f39,
                name: "Point-of-Service (POS) Entry Mode",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f3au16,
            DataElement {
                tag: 0x9f3a,
                name: "Amount, Reference Currency",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f3bu16,
            DataElement {
                tag: 0x9f3b,
                name: "Application Reference Currency",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f3cu16,
            DataElement {
                tag: 0x9f3c,
                name: "Transaction Reference Currency Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f3du16,
            DataElement {
                tag: 0x9f3d,
                name: "Transaction Reference Currency Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f40u16,
            DataElement {
                tag: 0x9f40,
                name: "Additional Terminal Capabilities",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f41u16,
            DataElement {
                tag: 0x9f41,
                name: "Transaction Sequence Counter",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f42u16,
            DataElement {
                tag: 0x9f42,
                name: "Application Currency Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f43u16,
            DataElement {
                tag: 0x9f43,
                name: "Application Reference Currency Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f44u16,
            DataElement {
                tag: 0x9f44,
                name: "Application Currency Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f45u16,
            DataElement {
                tag: 0x9f45,
                name: "Data Authentication Code",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f46u16,
            DataElement {
                tag: 0x9f46,
                name: "ICC Public Key Certificate",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f47u16,
            DataElement {
                tag: 0x9f47,
                name: "ICC Public Key Exponent",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f48u16,
            DataElement {
                tag: 0x9f48,
                name: "ICC Public Key Remainder",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4au16,
            DataElement {
                tag: 0x9f4a,
                name: "Static Data Authentication Tag List",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4bu16,
            DataElement {
                tag: 0x9f4b,
                name: "Signed Dynamic Application Data",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4cu16,
            DataElement {
                tag: 0x9f4c,
                name: "ICC Dynamic Number",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4du16,
            DataElement {
                tag: 0x9f4d,
                name: "Log Entry",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4eu16,
            DataElement {
                tag: 0x9f4e,
                name: "Merchant Name and Location",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0x9f4fu16,
            DataElement {
                tag: 0x9f4f,
                name: "Log Format",
                short_name: None,
                typ: ElementType::Binary,
            }
        ),
        (
            0xbf0cu16,
            DataElement {
                tag: 0xbf0c,
                name: "FCI Issuer Discretionary Data",
                short_name: None,
                typ: ElementType::Template,
            }
        ),
    ]);
}
