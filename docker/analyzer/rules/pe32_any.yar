rule Any_PE32
{
  meta:
    author = "JUMAL-test"
    description = "Match any PE by MZ header (simple test rule)"

  strings:
    $mz = "MZ" at 0

  condition:
    $mz
}
