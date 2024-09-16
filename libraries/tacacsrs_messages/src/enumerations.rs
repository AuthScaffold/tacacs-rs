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
            TacacsMajorVersion::TacacsPlusMajor1 => write!(f, "TACACS_PLUS_MAJOR_1"),
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
            TacacsMinorVersion::TacacsPlusMinorVerDefault => write!(f, "TACACS_PLUS_MINOR_VER_DEFAULT"),
            TacacsMinorVersion::TacacsPlusMinorVerOne => write!(f, "TACACS_PLUS_MINOR_VER_ONE"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsType {
    TacPlusAuthentication = 0x1,
    TacPlusAuthorisation = 0x2,
    TacPlusAccounting = 0x3,
}

impl fmt::Display for TacacsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TacacsType::TacPlusAuthentication => write!(f, "TAC_PLUS_AUTHENTICATION"),
            TacacsType::TacPlusAuthorisation => write!(f, "TAC_PLUS_AUTHORISATION"),
            TacacsType::TacPlusAccounting => write!(f, "TAC_PLUS_ACCOUNTING"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsFlags: u8 {
        const TAC_PLUS_UNENCRYPTED_FLAG = 0x01;
        const TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsAuthenticationAction {
    TacPlusAuthenLogin = 0x1,
    TacPlusAuthenChpass = 0x2,
    TacPlusAuthenSendauth = 0x3,
}

impl fmt::Display for TacacsAuthenticationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TacacsAuthenticationAction::TacPlusAuthenLogin => write!(f, "TAC_PLUS_AUTHEN_LOGIN"),
            TacacsAuthenticationAction::TacPlusAuthenChpass => write!(f, "TAC_PLUS_AUTHEN_CHPASS"),
            TacacsAuthenticationAction::TacPlusAuthenSendauth => write!(f, "TAC_PLUS_AUTHEN_SENDAUTH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            TacacsAuthenticationType::TacPlusAuthenTypeNotSet => write!(f, "TAC_PLUS_AUTHEN_TYPE_NOT_SET"),
            TacacsAuthenticationType::TacPlusAuthenTypeAscii => write!(f, "TAC_PLUS_AUTHEN_TYPE_ASCII"),
            TacacsAuthenticationType::TacPlusAuthenTypePap => write!(f, "TAC_PLUS_AUTHEN_TYPE_PAP"),
            TacacsAuthenticationType::TacPlusAuthenTypeChap => write!(f, "TAC_PLUS_AUTHEN_TYPE_CHAP"),
            TacacsAuthenticationType::TacPlusAuthenTypeMschap => write!(f, "TAC_PLUS_AUTHEN_TYPE_MSCHAP"),
            TacacsAuthenticationType::TacPlusAuthenTypeMschapv2 => write!(f, "TAC_PLUS_AUTHEN_TYPE_MSCHAPV2"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            TacacsAuthenticationService::TacPlusAuthenSvcNone => write!(f, "TAC_PLUS_AUTHEN_SVC_NONE"),
            TacacsAuthenticationService::TacPlusAuthenSvcLogin => write!(f, "TAC_PLUS_AUTHEN_SVC_LOGIN"),
            TacacsAuthenticationService::TacPlusAuthenSvcEnable => write!(f, "TAC_PLUS_AUTHEN_SVC_ENABLE"),
            TacacsAuthenticationService::TacPlusAuthenSvcPpp => write!(f, "TAC_PLUS_AUTHEN_SVC_PPP"),
            TacacsAuthenticationService::TacPlusAuthenSvcPt => write!(f, "TAC_PLUS_AUTHEN_SVC_PT"),
            TacacsAuthenticationService::TacPlusAuthenSvcRcmd => write!(f, "TAC_PLUS_AUTHEN_SVC_RCMD"),
            TacacsAuthenticationService::TacPlusAuthenSvcX25 => write!(f, "TAC_PLUS_AUTHEN_SVC_X25"),
            TacacsAuthenticationService::TacPlusAuthenSvcNasi => write!(f, "TAC_PLUS_AUTHEN_SVC_NASI"),
            TacacsAuthenticationService::TacPlusAuthenSvcFwproxy => write!(f, "TAC_PLUS_AUTHEN_SVC_FWPROXY"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass => write!(f, "TAC_PLUS_AUTHEN_STATUS_PASS"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail => write!(f, "TAC_PLUS_AUTHEN_STATUS_FAIL"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata => write!(f, "TAC_PLUS_AUTHEN_STATUS_GETDATA"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser => write!(f, "TAC_PLUS_AUTHEN_STATUS_GETUSER"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass => write!(f, "TAC_PLUS_AUTHEN_STATUS_GETPASS"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusRestart => write!(f, "TAC_PLUS_AUTHEN_STATUS_RESTART"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusError => write!(f, "TAC_PLUS_AUTHEN_STATUS_ERROR"),
            TacacsAuthenticationStatus::TacPlusAuthenStatusFollow => write!(f, "TAC_PLUS_AUTHEN_STATUS_FOLLOW"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TacacsAuthenicationReplyFlags: u8 {
        const TAC_PLUS_AUTHEN_FLAG_NOECHO = 0x1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsAuthenticationContinueStatus {
    TacPlusContinueFlagAbort = 0x01,
}

impl fmt::Display for TacacsAuthenticationContinueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TacacsAuthenticationContinueStatus::TacPlusContinueFlagAbort => write!(f, "TAC_PLUS_CONTINUE_FLAG_ABORT"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet => write!(f, "TAC_PLUS_AUTHEN_METH_NOT_SET"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodNone => write!(f, "TAC_PLUS_AUTHEN_METH_NONE"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodKrb5 => write!(f, "TAC_PLUS_AUTHEN_METH_KRB5"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodLine => write!(f, "TAC_PLUS_AUTHEN_METH_LINE"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodEnable => write!(f, "TAC_PLUS_AUTHEN_METH_ENABLE"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodLocal => write!(f, "TAC_PLUS_AUTHEN_METH_LOCAL"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus => write!(f, "TAC_PLUS_AUTHEN_METH_TACACSPLUS"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodGuest => write!(f, "TAC_PLUS_AUTHEN_METH_GUEST"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodRadius => write!(f, "TAC_PLUS_AUTHEN_METH_RADIUS"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodKrb4 => write!(f, "TAC_PLUS_AUTHEN_METH_KRB4"),
            TacacsAuthenticationMethod::TacPlusAuthenMethodRcmd => write!(f, "TAC_PLUS_AUTHEN_METH_RCMD"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsAuthorizationStatus {
    TacPlusPassAdd = 0x01,
    TacPlusPassRepl = 0x02,
    TacPlusFail = 0x10,
    TacPlusError = 0x11,
    TacPlusFollow = 0x21,
}

impl fmt::Display for TacacsAuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TacacsAuthorizationStatus::TacPlusPassAdd => write!(f, "TAC_PLUS_PASS_ADD"),
            TacacsAuthorizationStatus::TacPlusPassRepl => write!(f, "TAC_PLUS_PASS_REPL"),
            TacacsAuthorizationStatus::TacPlusFail => write!(f, "TAC_PLUS_FAIL"),
            TacacsAuthorizationStatus::TacPlusError => write!(f, "TAC_PLUS_ERROR"),
            TacacsAuthorizationStatus::TacPlusFollow => write!(f, "TAC_PLUS_FOLLOW"),
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