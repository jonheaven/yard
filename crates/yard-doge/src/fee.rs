use yard_core::{FEE_PER_KB_KOINU, KOINU_PER_DOGE, SOFT_DUST_KOINU};

/// 0.01 DOGE per started kilobyte of serialized size.
pub fn fee_for_size(size: usize) -> u64 {
    let started_kb = size.saturating_add(999) / 1000;
    started_kb.max(1) as u64 * FEE_PER_KB_KOINU
}

pub fn estimate_legacy_size(n_in: usize, n_p2pkh_out: usize, opreturn_payload: usize) -> usize {
    let mut n = 4 + 4; // version + locktime
    n += compact_len(n_in);
    n += n_in * 148; // P2PKH input estimate
    let extra = if opreturn_payload > 0 { 1 } else { 0 };
    let n_out = n_p2pkh_out + extra;
    n += compact_len(n_out);
    n += n_p2pkh_out * 34;
    if opreturn_payload > 0 {
        let script_len = 1 + 1 + opreturn_payload; // OP_RETURN + push + data (payload < 76)
        n += 8 + compact_len(script_len) + script_len;
    }
    n
}

fn compact_len(n: usize) -> usize {
    yard_core::compact_size_len(n)
}

pub fn parse_doge_to_koinu(s: &str) -> Result<u64, crate::Error> {
    let s = s.trim();
    if s.is_empty() {
        return Err(crate::Error::Amount("empty DOGE amount".into()));
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 8 {
        return Err(crate::Error::Amount("more than 8 decimal places".into()));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(crate::Error::Amount(format!("invalid DOGE amount {s}")));
    }
    let whole_n: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| crate::Error::Amount("whole part overflow".into()))?
    };
    let mut frac_pad = frac.to_string();
    while frac_pad.len() < 8 {
        frac_pad.push('0');
    }
    let frac_n: u64 = if frac_pad.is_empty() {
        0
    } else {
        frac_pad
            .parse()
            .map_err(|_| crate::Error::Amount("frac overflow".into()))?
    };
    whole_n
        .checked_mul(KOINU_PER_DOGE)
        .and_then(|w| w.checked_add(frac_n))
        .ok_or_else(|| crate::Error::Amount("koinu overflow".into()))
}

pub fn koinu_to_doge_string(koinu: u64) -> String {
    let whole = koinu / KOINU_PER_DOGE;
    let frac = koinu % KOINU_PER_DOGE;
    if frac == 0 {
        format!("{whole}")
    } else {
        format!("{whole}.{frac:08}")
            .trim_end_matches('0')
            .to_string()
    }
}

pub fn is_soft_dust(koinu: u64) -> bool {
    koinu < SOFT_DUST_KOINU
}
