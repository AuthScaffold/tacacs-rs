use std::fmt;
use bitflags::bitflags;
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsMajorVersion {
    TacacsPlusMajor1 = 0xc,
}

impl fmt::Display for TacacsMajorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacacsPlusMajor1 => write!(f, "TAC_PLUS_MAJOR_VER"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsMinorVersion {
    TacacsPlusMinorVerDefault = 0x0,
    TacacsPlusMinorVerOne = 0x1,
}

impl fmt::Display for TacacsMinorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacacsPlusMinorVerDefault => {
                write!(f, "TAC_PLUS_MINOR_VER_DEFAULT")
            }
            Self::TacacsPlusMinorVerOne => write!(f, "TAC_PLUS_MINOR_VER_ONE"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsType {
    TacPlusAuthentication = 0x1,
    TacPlusAuthorisation = 0x2,
    TacPlusAccounting = 0x3,
}

impl fmt::Display for TacacsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthentication => write!(f, "TAC_PLUS_AUTHENTICATION"),
            Self::TacPlusAuthorisation => write!(f, "TAC_PLUS_AUTHORISATION"),
            Self::TacPlusAccounting => write!(f, "TAC_PLUS_ACCOUNTING"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsFlags: u8 {
        const TAC_PLUS_UNENCRYPTED_FLAG = 0x01;
        const TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04;
        // These nonstandard flags use TACACS+ header bits that RFC 8907
        // reserves. Other TACACS+ implementations can reject these flags or
        // interpret them differently.
        const TAC_PLUS_CUSTOM_FLAG_1 = 0x40;
        const TAC_PLUS_CUSTOM_FLAG_2 = 0x80;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAuthenticationAction {
    TacPlusAuthenLogin = 0x1,
    TacPlusAuthenChpass = 0x2,
    TacPlusAuthenSendauth = 0x4,
}

impl fmt::Display for TacacsAuthenticationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthenLogin => write!(f, "TAC_PLUS_AUTHEN_LOGIN"),
            Self::TacPlusAuthenChpass => write!(f, "TAC_PLUS_AUTHEN_CHPASS"),
            Self::TacPlusAuthenSendauth => {
                write!(f, "TAC_PLUS_AUTHEN_SENDAUTH")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAuthenticationType {
    TacPlusAuthenTypeNotSet = 0x00,
    TacPlusAuthenTypeAscii = 0x1,
    TacPlusAuthenTypePap = 0x2,
    TacPlusAuthenTypeChap = 0x3,
    TacPlusAuthenTypeMschap = 0x5,
    TacPlusAuthenTypeMschapv2 = 0x6,
}

impl fmt::Display for TacacsAuthenticationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthenTypeNotSet => {
                write!(f, "TAC_PLUS_AUTHEN_TYPE_NOT_SET")
            }
            Self::TacPlusAuthenTypeAscii => {
                write!(f, "TAC_PLUS_AUTHEN_TYPE_ASCII")
            }
            Self::TacPlusAuthenTypePap => write!(f, "TAC_PLUS_AUTHEN_TYPE_PAP"),
            Self::TacPlusAuthenTypeChap => {
                write!(f, "TAC_PLUS_AUTHEN_TYPE_CHAP")
            }
            Self::TacPlusAuthenTypeMschap => {
                write!(f, "TAC_PLUS_AUTHEN_TYPE_MSCHAP")
            }
            Self::TacPlusAuthenTypeMschapv2 => {
                write!(f, "TAC_PLUS_AUTHEN_TYPE_MSCHAPV2")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAuthenticationService {
    TacPlusAuthenSvcNone = 0x0,
    TacPlusAuthenSvcLogin = 0x1,
    TacPlusAuthenSvcEnable = 0x2,
    TacPlusAuthenSvcPpp = 0x3,
    TacPlusAuthenSvcPt = 0x5,
    TacPlusAuthenSvcRcmd = 0x6,
    TacPlusAuthenSvcX25 = 0x7,
    TacPlusAuthenSvcNasi = 0x8,
    TacPlusAuthenSvcFwproxy = 0x9,
}

impl fmt::Display for TacacsAuthenticationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthenSvcNone => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_NONE")
            }
            Self::TacPlusAuthenSvcLogin => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_LOGIN")
            }
            Self::TacPlusAuthenSvcEnable => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_ENABLE")
            }
            Self::TacPlusAuthenSvcPpp => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_PPP")
            }
            Self::TacPlusAuthenSvcPt => write!(f, "TAC_PLUS_AUTHEN_SVC_PT"),
            Self::TacPlusAuthenSvcRcmd => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_RCMD")
            }
            Self::TacPlusAuthenSvcX25 => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_X25")
            }
            Self::TacPlusAuthenSvcNasi => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_NASI")
            }
            Self::TacPlusAuthenSvcFwproxy => {
                write!(f, "TAC_PLUS_AUTHEN_SVC_FWPROXY")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAuthenticationStatus {
    TacPlusAuthenStatusPass = 0x1,
    TacPlusAuthenStatusFail = 0x2,
    TacPlusAuthenStatusGetdata = 0x3,
    TacPlusAuthenStatusGetuser = 0x4,
    TacPlusAuthenStatusGetpass = 0x5,
    TacPlusAuthenStatusRestart = 0x6,
    TacPlusAuthenStatusError = 0x7,
    TacPlusAuthenStatusFollow = 0x21,
}

impl fmt::Display for TacacsAuthenticationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthenStatusPass => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_PASS")
            }
            Self::TacPlusAuthenStatusFail => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_FAIL")
            }
            Self::TacPlusAuthenStatusGetdata => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_GETDATA")
            }
            Self::TacPlusAuthenStatusGetuser => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_GETUSER")
            }
            Self::TacPlusAuthenStatusGetpass => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_GETPASS")
            }
            Self::TacPlusAuthenStatusRestart => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_RESTART")
            }
            Self::TacPlusAuthenStatusError => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_ERROR")
            }
            Self::TacPlusAuthenStatusFollow => {
                write!(f, "TAC_PLUS_AUTHEN_STATUS_FOLLOW")
            }
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsAuthenticationReplyFlags: u8 {
        const TAC_PLUS_REPLY_FLAG_NOECHO = 0x1;
    }
}

pub type TacacsAuthenicationReplyFlags = TacacsAuthenticationReplyFlags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsAuthenticationContinueFlags: u8 {
        const TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsAuthenticationContinueStatus {
    TacPlusContinueFlagAbort = 0x01,
}

impl fmt::Display for TacacsAuthenticationContinueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusContinueFlagAbort => {
                write!(f, "TAC_PLUS_CONTINUE_FLAG_ABORT")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAuthenticationMethod {
    TacPlusAuthenMethodNotSet = 0x00,
    TacPlusAuthenMethodNone = 0x01,
    TacPlusAuthenMethodKrb5 = 0x02,
    TacPlusAuthenMethodLine = 0x03,
    TacPlusAuthenMethodEnable = 0x04,
    TacPlusAuthenMethodLocal = 0x05,
    TacPlusAuthenMethodTacacsplus = 0x06,
    TacPlusAuthenMethodGuest = 0x08,
    TacPlusAuthenMethodRadius = 0x10,
    TacPlusAuthenMethodKrb4 = 0x11,
    TacPlusAuthenMethodRcmd = 0x20,
}

impl fmt::Display for TacacsAuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAuthenMethodNotSet => {
                write!(f, "TAC_PLUS_AUTHEN_METH_NOT_SET")
            }
            Self::TacPlusAuthenMethodNone => {
                write!(f, "TAC_PLUS_AUTHEN_METH_NONE")
            }
            Self::TacPlusAuthenMethodKrb5 => {
                write!(f, "TAC_PLUS_AUTHEN_METH_KRB5")
            }
            Self::TacPlusAuthenMethodLine => {
                write!(f, "TAC_PLUS_AUTHEN_METH_LINE")
            }
            Self::TacPlusAuthenMethodEnable => {
                write!(f, "TAC_PLUS_AUTHEN_METH_ENABLE")
            }
            Self::TacPlusAuthenMethodLocal => {
                write!(f, "TAC_PLUS_AUTHEN_METH_LOCAL")
            }
            Self::TacPlusAuthenMethodTacacsplus => {
                write!(f, "TAC_PLUS_AUTHEN_METH_TACACSPLUS")
            }
            Self::TacPlusAuthenMethodGuest => {
                write!(f, "TAC_PLUS_AUTHEN_METH_GUEST")
            }
            Self::TacPlusAuthenMethodRadius => {
                write!(f, "TAC_PLUS_AUTHEN_METH_RADIUS")
            }
            Self::TacPlusAuthenMethodKrb4 => {
                write!(f, "TAC_PLUS_AUTHEN_METH_KRB4")
            }
            Self::TacPlusAuthenMethodRcmd => {
                write!(f, "TAC_PLUS_AUTHEN_METH_RCMD")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
/// TACACS+ authorization reply status octet values.
///
/// The `status` field of an authorization REPLY body contains one of these
/// values. RFC 8907 section 6.2 defines the values.
pub enum TacacsAuthorizationStatus {
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_ADD` (`0x01`) accepts the request.
    ///
    /// The client appends the returned arguments to the submitted arguments.
    TacPlusPassAdd = 0x01,
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_REPL` (`0x02`) accepts the request.
    ///
    /// The client replaces the submitted arguments with the returned arguments.
    TacPlusPassRepl = 0x02,
    /// `TAC_PLUS_AUTHOR_STATUS_FAIL` (`0x10`) denies the requested operation.
    TacPlusFail = 0x10,
    /// `TAC_PLUS_AUTHOR_STATUS_ERROR` (`0x11`) reports an authorization error.
    ///
    /// The server failed to process the request, or a protocol error occurred.
    TacPlusError = 0x11,
    /// `TAC_PLUS_AUTHOR_STATUS_FOLLOW` (`0x21`) requires deployment-specific handling.
    TacPlusFollow = 0x21,
}

impl fmt::Display for TacacsAuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusPassAdd => write!(f, "TAC_PLUS_AUTHOR_STATUS_PASS_ADD"),
            Self::TacPlusPassRepl => write!(f, "TAC_PLUS_AUTHOR_STATUS_PASS_REPL"),
            Self::TacPlusFail => write!(f, "TAC_PLUS_AUTHOR_STATUS_FAIL"),
            Self::TacPlusError => write!(f, "TAC_PLUS_AUTHOR_STATUS_ERROR"),
            Self::TacPlusFollow => write!(f, "TAC_PLUS_AUTHOR_STATUS_FOLLOW"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsAccountingFlags: u8 {
        const START = 0x02;
        const STOP = 0x04;
        const WATCHDOG = 0x08;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TacacsAccountingStatus {
    TacPlusAcctStatusSuccess = 0x01,
    TacPlusAcctStatusError = 0x02,
    TacPlusAcctStatusFollow = 0x21,
}

impl fmt::Display for TacacsAccountingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TacPlusAcctStatusSuccess => {
                write!(f, "TAC_PLUS_ACCT_STATUS_SUCCESS")
            }
            Self::TacPlusAcctStatusError => {
                write!(f, "TAC_PLUS_ACCT_STATUS_ERROR")
            }
            Self::TacPlusAcctStatusFollow => {
                write!(f, "TAC_PLUS_ACCT_STATUS_FOLLOW")
            }
        }
    }
}
