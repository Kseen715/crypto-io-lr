$build_path = ".\build\cifs.exe"
$byte_limit = 100000
$ecb_log_file = ".\temp\ecb.log"
$cbc_log_file = ".\temp\cbc.log"
$cfb_log_file = ".\temp\cfb.log"

Write-Host "<] Run standard tests on PNG files"
.\tests\win_test_png.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with ECB mode"

$bit_to_flip = 0
& .\tests\flip-bit.py .\tests\kokkoro-astrum.png $bit_to_flip .\temp\kokkoro-astrum-$bit_to_flip.png

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c ecb -o .\temp\demo-png-ecb.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png-ecb.enc -c ecb -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\changed-bits.py .\temp\demo-png.enc .\temp\demo-png-ecb.enc --limit $byte_limit > $ecb_log_file
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with CBC mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c cbc -o .\temp\demo-png-cbc.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png-cbc.enc -c cbc -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with CFB mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c cfb -o .\temp\demo-png-cfb.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png-cfb.enc -c cfb -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }