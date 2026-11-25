/-! judged: the renewal window (judged/renew.py `min_when_days`).
Renewal is attempted every `step` hours from `w` days before expiry. After `k` failed attempts the next one
must still land at least `s` days before expiry:  24*w - k*step >= 24*s.  The smallest whole `w` is a ceiling
division, proved here safe (it satisfies the constraint) and tight (one day less does not). Integer hours. -/

def minWhen (k step s : Nat) : Nat := (24 * s + k * step + 23) / 24

theorem minWhen_safe (k step s : Nat) : 24 * s + k * step ≤ 24 * minWhen k step s := by
  unfold minWhen; omega

theorem minWhen_tight (k step s : Nat) (h : 0 < minWhen k step s) :
    24 * (minWhen k step s - 1) < 24 * s + k * step := by
  unfold minWhen at *; omega

/-- More tolerated failures never shrink the window. -/
theorem minWhen_mono (k1 k2 step s : Nat) (h : k1 ≤ k2) : minWhen k1 step s ≤ minWhen k2 step s := by
  unfold minWhen
  have : k1 * step ≤ k2 * step := Nat.mul_le_mul_right step h
  omega
