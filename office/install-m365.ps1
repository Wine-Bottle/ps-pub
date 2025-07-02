# Download and install M365 apps
# Language: Match OS; Proofing includes: zh-cn, zh-tw 
cd $env:TEMP; mkdir odt; cd odt;
$webpage = iwr -UseBasicParsing https://www.microsoft.com/en-us/download/details.aspx?id=49117
curl.exe -OJL ($webpage.Links | ? href -Like "https://download.microsoft.com/download/*officedeploymenttool_*.exe").href
$setup = (ls .\officedeploymenttool_*.exe).FullName
Start-Process $setup -ArgumentList "/extract:$pwd /quiet"
$xml = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise" MigrateArch="TRUE">
    <Product ID="O365ProPlusRetail">
      <Language ID="MatchOS" />
      <ExcludeApp ID="Access" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="OneDrive" />
      <ExcludeApp ID="Publisher" />
      <ExcludeApp ID="Teams" />
      <ExcludeApp ID="Bing" />
    </Product>
    <Product ID="LanguagePack">
      <Language ID="MatchOS" />
      <ExcludeApp ID="Bing" />
    </Product>
    <Product ID="ProofingTools">
      <Language ID="zh-cn" />
      <Language ID="zh-tw" />
    </Product>
  </Add>
  <Updates Enabled="TRUE" />
  <RemoveMSI>
    <IgnoreProduct ID="PrjPro" />
    <IgnoreProduct ID="PrjStd" />
    <IgnoreProduct ID="VisPro" />
    <IgnoreProduct ID="VisStd" />
  </RemoveMSI>
  <Display Level="Full" AcceptEULA="TRUE" />
</Configuration>
"@
$xml | Out-File -FilePath "o365.xml" # Write XML to the working dir
# curl.exe -LJO "https://officecdn.microsoft.com/pr/wsus/setup.exe" # DL ODT setup.exe from WSUS, not always stable
Start-Process "setup.exe" -ArgumentList "/configure .\o365.xml" -Wait # Execute ODT installation