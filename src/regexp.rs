use regex::{Regex, RegexBuilder};

/// REFERENCE_REGEXP is the full supported format of a reference. The regexp
// is anchored and has capturing groups for name, tag, and digest components.
pub const REFERENCE_REGEXP: &str = r"^((?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?/)?[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?)(?::([\w][\w.-]{0,127}))?(?:@([A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}))?$";

pub fn must_compile(r: &str) -> Regex {
    RegexBuilder::new(r)
        .size_limit(10 * (1 << 21))
        .build()
        .unwrap()
}
