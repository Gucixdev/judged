/-! judged: the expiry band and the once-per-band rule (judged/core.py `band`, `due`).
Model: whole days as Int, lead days as a list. The Python uses float days; the proofs cover the integer model and
tests/test_bands_spec.py holds the code to the same specification on a grid. -/

def covering (d : Int) (ls : List Int) : List Int := ls.filter (fun t => decide (d ≤ t))

/-- -1 once expired, the smallest lead threshold that still covers `d`, none while far from expiry. -/
def band (d : Int) (ls : List Int) : Option Int :=
  if d < 0 then some (-1) else (covering d ls).min?

theorem band_expired (d : Int) (ls : List Int) (h : d < 0) : band d ls = some (-1) := by
  simp [band, h]

/-- A real band is one of the configured thresholds, it covers `d`, and no smaller threshold does. -/
theorem band_spec (d : Int) (ls : List Int) (b : Int) (hd : 0 ≤ d) (h : band d ls = some b) :
    b ∈ ls ∧ d ≤ b ∧ ∀ t ∈ ls, d ≤ t → b ≤ t := by
  have hn : ¬ d < 0 := by omega
  simp [band, hn] at h
  rw [List.min?_eq_some_iff] at h
  obtain ⟨hb, hmin⟩ := h
  simp [covering, List.mem_filter] at hb hmin
  exact ⟨hb.1, hb.2, fun t ht hdt => hmin t ht hdt⟩

/-- Closer to expiry never gives a less urgent band: if `d2` is in band `b2`, then any `d1 ≤ d2` (not expired)
is in a band `b1 ≤ b2`. -/
theorem band_mono (d1 d2 : Int) (ls : List Int) (b2 : Int) (h1 : 0 ≤ d1) (h12 : d1 ≤ d2)
    (h : band d2 ls = some b2) :
    ∃ b1, band d1 ls = some b1 ∧ b1 ≤ b2 := by
  have h2 : 0 ≤ d2 := by omega
  obtain ⟨hmem, hcov, _⟩ := band_spec d2 ls b2 h2 h
  have hn : ¬ d1 < 0 := by omega
  have hin : b2 ∈ covering d1 ls := by
    simp [covering, List.mem_filter]; exact ⟨hmem, by omega⟩
  have hne : (covering d1 ls) ≠ [] := by
    intro e; rw [e] at hin; simp at hin
  obtain ⟨m, hm⟩ : ∃ m, (covering d1 ls).min? = some m := by
    cases hmin : (covering d1 ls).min? with
    | none => simp [List.min?_eq_none_iff] at hmin; exact absurd hmin hne
    | some m => exact ⟨m, rfl⟩
  refine ⟨m, by simp [band, hn, hm], ?_⟩
  rw [List.min?_eq_some_iff] at hm
  exact hm.2 b2 hin

/-- An alert fires when the band is more urgent than the one already reported (or none was). -/
def alerts (prev : Option Int) (b : Int) : Bool :=
  match prev with
  | none => true
  | some p => decide (b < p)

/-- After an alert the stored band is `b`, and the same band never alerts twice. -/
theorem no_repeat (b : Int) : alerts (some b) b = false := by simp [alerts]

/-- An alert is always a step towards expiry. -/
theorem alert_is_progress (p b : Int) (h : alerts (some p) b = true) : b < p := by simpa [alerts] using h

/-- A renewal (band back to a larger one or none) leaves the stored band alone and the next cycle starts at the
top again: any threshold in `ls` alerts once the state was cleared. -/
theorem fresh_cycle_alerts (b : Int) : alerts none b = true := by simp [alerts]
