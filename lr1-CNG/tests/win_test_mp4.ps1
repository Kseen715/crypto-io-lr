$build_path = ".\build\cifs.exe"

Write-Host "<] Generating key and IV"
& $build_path -m keygen -g .\temp\key.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m iv -g .\temp\iv.bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on mp4 file with ECB mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f  ".\tests\nc-video.mp4" -c ecb -o ".\temp\demo-mp4.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f ".\temp\demo-mp4.enc" -c ecb -o ".\temp\demo-mp4-dec.mp4"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\nc-video.mp4 .\temp\demo-mp4-dec.mp4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on mp4 file with CBC mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f  ".\tests\nc-video.mp4" -c cbc -o ".\temp\demo-mp4.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f ".\temp\demo-mp4.enc" -c cbc -o ".\temp\demo-mp4-dec.mp4"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\nc-video.mp4 .\temp\demo-mp4-dec.mp4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "<] Test on mp4 file with CFB mode"
& $build_path -m enc -k .\temp\key.bin -i .\temp\iv.bin -f  ".\tests\nc-video.mp4" -c cfb -o ".\temp\demo-mp4.enc"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $build_path -m dec -k .\temp\key.bin -i .\temp\iv.bin -f ".\temp\demo-mp4.enc" -c cfb -o ".\temp\demo-mp4-dec.mp4"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\tests\win_compare_files.ps1 .\tests\nc-video.mp4 .\temp\demo-mp4-dec.mp4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
