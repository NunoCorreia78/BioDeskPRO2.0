 = Get-Content -Path 'src/BioDesk.ViewModels/UserControls/TerapiasBioenergeticasUserControlViewModel.cs' -Raw; .Length; .Substring(0,[Math]::Min(.Length,6000))
