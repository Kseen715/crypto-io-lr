$build_path = ".\build\cifs.exe"
$file_to_test = ".\tests\lorem.txt"
$ecb_log_file = ".\temp\ecb.log"
$cbc_log_file = ".\temp\cbc.log"
$cfb_log_file = ".\temp\cfb.log"
$bits_to_flip = @(0, 2, 8, 16, 32, 64, 128, 256, 384, 512, 768, 1024, 1536, 2048, 2500, 3084, 3500, 4096, 4500, 5000, 5500, 6000, 6500, 6750, 7000, 7250, 7500, 7750, 8192)  # Define the array with values to test

# copy test file to temp
Copy-Item $file_to_test .\temp\aval
$file_to_test = ".\temp\aval"

# clear log files
Remove-Item $ecb_log_file
Remove-Item $cbc_log_file
Remove-Item $cfb_log_file

Write-Host "<] Generate key and IV"
& $build_path -m keygen -g .\temp\key.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m iv -g .\temp\iv.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Generate reference test file with ECB mode for txt file"

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f $file_to_test -c ecb -o "$file_to_test.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Run tests for ECB mode"

foreach ($bit_to_flip in $bits_to_flip) {
    & .\tests\flip-bit.py $file_to_test $bit_to_flip "$file_to_test-$bit_to_flip.txt"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f "$file_to_test-$bit_to_flip.txt" -c ecb -o "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $log_entry = "$bit_to_flip, "
    $count_bit_diff_output = & .\tests\count-bit-diff.py "$file_to_test.enc" "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $log_entry += $count_bit_diff_output
    $log_entry >> $ecb_log_file
}

Write-Host "<] Generate reference test file with CBC mode for txt file"

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f $file_to_test -c cbc -o "$file_to_test.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Run tests for CBC mode"

foreach ($bit_to_flip in $bits_to_flip) {
    & .\tests\flip-bit.py $file_to_test $bit_to_flip "$file_to_test-$bit_to_flip.txt"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f "$file_to_test-$bit_to_flip.txt" -c cbc -o "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $log_entry = "$bit_to_flip, "
    $count_bit_diff_output = & .\tests\count-bit-diff.py "$file_to_test.enc" "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $log_entry += $count_bit_diff_output
    $log_entry >> $cbc_log_file
}

Write-Host "<] Generate reference test file with CFB mode for txt file"

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f $file_to_test -c cfb -o "$file_to_test.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Run tests for CFB mode"

foreach ($bit_to_flip in $bits_to_flip) {
    & .\tests\flip-bit.py $file_to_test $bit_to_flip "$file_to_test-$bit_to_flip.txt"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f "$file_to_test-$bit_to_flip.txt" -c cfb -o "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $log_entry = "$bit_to_flip, "
    $count_bit_diff_output = & .\tests\count-bit-diff.py "$file_to_test.enc" "$file_to_test-$bit_to_flip.enc"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $log_entry += $count_bit_diff_output
    $log_entry >> $cfb_log_file
}

Write-Host "<] Plotting graph"

& .\tests\make-graphs.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Done"

Write-Host "<] Removing temp files"
Remove-Item .\temp\aval*
