$build_path = ".\build\cifs.exe"

Write-Host "<] Test on png file"
& $build_path -m keygen -g .\temp\key.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m iv -g .\temp\iv.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f .\tests\kokkoro-astrum.png -c no -o .\temp\demo-png.enc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f .\temp\demo-png.enc -c no -o .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\kokkoro-astrum.png .\temp\demo-png-dec.png
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

