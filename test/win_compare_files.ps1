# Get files from cmd
$file = $args[0]
$file2 = $args[1]
# Get the file hashes
$hashSrc = Get-FileHash $file -Algorithm "SHA256"
$hashDest = Get-FileHash $file2 -Algorithm "SHA256"
# Compare the hashes & note this in the log
If ($hashSrc.Hash -ne $hashDest.Hash)
{
  Add-Content -Path $cLogFile -Value " Source File Hash: $hashSrc does not
  equal Existing Destination File Hash: $hashDest the files are NOT EQUAL."
}
Else 
{
  Add-Content -Path $cLogFile -Value " Source File Hash: $hashSrc equals
  Existing Destination File Hash: $hashDest the files are EQUAL."
}