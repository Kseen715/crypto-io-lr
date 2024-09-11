# Get files from cmd
$file = $args[0]
$file2 = $args[1]
# Get the file hashes
$hashSrc = Get-FileHash $file -Algorithm "SHA256"
$hashDest = Get-FileHash $file2 -Algorithm "SHA256"
# Compare the hashes & note this in the log
If ($hashSrc.Hash -ne $hashDest.Hash)
{
  $hashSrcBytes = [System.Convert]::FromBase64String($hashSrc.Hash)
  $hashDestBytes = [System.Convert]::FromBase64String($hashDest.Hash)
  $diffBytes = @()
    for ($i = 0; $i -lt $hashSrcBytes.Length; $i++) {
        $diffBytes += $hashSrcBytes[$i] - $hashDestBytes[$i]
    }
  $hexDiff = ($diffBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
  Write-Output "<] The files are NOT EQUAL. The difference is: $hexDiff"
}
Else 
{
  Write-Output "<] The files are EQUAL."
}