# judged: the smallest whole renewal window w (days before expiry) such that `retries` failed attempts, each
# `step` hours apart, still leave the next attempt `safety` days before expiry.
param retries >= 0 integer;
param step > 0;
param safety >= 0;
var w >= 0 integer;
minimize window: w;
s.t. survives: 24 * w - retries * step >= 24 * safety;
