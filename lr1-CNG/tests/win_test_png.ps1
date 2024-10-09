$build_path = ".\build\cifs.exe"

Write-Host "<] Generating key and IV"
& $build_path -m keygen -g .\temp\key.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m iv -g .\temp\iv.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with ECB mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c ecb -o .\temp\demo-png.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png.enc -c ecb -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with CBC mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c cbc -o .\temp\demo-png.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png.enc -c cbc -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on png file with CFB mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c cfb -o .\temp\demo-png.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png.enc -c cfb -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }