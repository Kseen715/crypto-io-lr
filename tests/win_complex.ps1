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


Write-Host "<] Test on mp4 file"
& $build_path -m keygen -g .\temp\key.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m iv -g .\temp\iv.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f  ".\tests\nc-video.mp4" -c "no" -o ".\temp\demo-mp4.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f ".\temp\demo-mp4.enc" -c "no" -o ".\temp\demo-mp4-dec.mp4"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\nc-video.mp4 .\temp\demo-mp4-dec.mp4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }