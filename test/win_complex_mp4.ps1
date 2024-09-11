.\test\win_make_key.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

.\test\win_make_iv.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

.\test\win_enc_file_mp4.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

.\test\win_dec_file_mp4.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }