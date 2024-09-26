from django.db import models
from django.utils import timezone

class Category(models.Model):
    name = models.CharField(max_length=500)

    def __str__(self):
        return self.name

# model for CA Form System
class CAServer(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    ca_server_planned = models.IntegerField(default=0)
    ca_server_performed = models.IntegerField(default=0)
    ca_server_non_compliant = models.IntegerField(default=0)
    ca_server_not_performed_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_server_non_compliant_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_server_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_server_severity = models.CharField(max_length=10, default='low')
    ca_server_color = models.CharField(max_length=20, default='badge-success')
    Evidence = models.CharField(max_length=500, default=None)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"CA Server report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"

class CANetwork(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    ca_network_planned = models.IntegerField(default=0)
    ca_network_performed = models.IntegerField(default=0)
    ca_network_non_compliant = models.IntegerField(default=0)
    ca_network_not_performed_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_network_non_compliant_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_network_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_network_severity = models.CharField(max_length=10, default='low')
    ca_network_color = models.CharField(max_length=20, default='badge-success')
    Evidence = models.CharField(max_length=500, default=None)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"CA Network report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"

class CADB(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    ca_db_planned = models.IntegerField(default=0)
    ca_db_performed = models.IntegerField(default=0)
    ca_db_non_compliant = models.IntegerField(default=0)
    ca_db_not_performed_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_db_non_compliant_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_db_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    ca_db_severity = models.CharField(max_length=10, default='low')
    ca_db_color = models.CharField(max_length=20, default='badge-success')
    Evidence = models.CharField(max_length=500, default=None)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"CA DB report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"



class Weightage(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    token = models.IntegerField(default=0)
    kri = models.CharField(max_length=500)
    weightage = models.DecimalField(max_digits=5, decimal_places=4)


class DRRiskScore(models.Model):
    kri=models.ForeignKey(Category, on_delete=models.CASCADE)
    month=models.CharField(max_length=500)
    riskScore = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    weightage = models.DecimalField(max_digits=5, decimal_places=4,default=0.0)

class RiskScore(models.Model):
    kri=models.ForeignKey(Category, on_delete=models.CASCADE)
    month=models.CharField(max_length=500)
    riskScore = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    weightage = models.DecimalField(max_digits=5, decimal_places=4,default=0.0)


class FinalRiskScore(models.Model):
    month=models.CharField(max_length=500)
    riskScore = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)


class Team(models.Model):
    team = models.CharField(max_length=500)
    owner = models.CharField(max_length=500)
    status = models.BooleanField(default=0)
    id = models.IntegerField(primary_key=True)


class Appsec(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    appsec = models.IntegerField(default=0)
    critical = models.IntegerField(default=0)
    high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    low = models.IntegerField(default=0)

    critical_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    high_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    medium_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    low_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)

    appsec_Critical_Risk_Score = models.IntegerField(default=0)
    appsec_High_Risk_Score = models.IntegerField(default=0)

    critical_Justification= models.CharField(max_length=500,default="NA")
    high_Justification= models.CharField(max_length=500,default="NA")

    appsec_Risk_Score = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)

    appsec_Evidence =  models.CharField(max_length=500,default=None)
  

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Appsec report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class VAPT(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    va_total_os = models.IntegerField(default=0)
    va_critical_os = models.IntegerField(default=0)
    va_high_os= models.IntegerField(default=0)
    va_medium_os = models.IntegerField(default=0)
    va_low_os = models.IntegerField(default=0)
    va_total_nonos = models.IntegerField(default=0)
    va_critical_nonos = models.IntegerField(default=0)
    va_high_nonos= models.IntegerField(default=0)
    va_medium_nonos = models.IntegerField(default=0)
    va_low_nonos = models.IntegerField(default=0)
    total_os = models.IntegerField(default=0)
    va_eos_in_tool = models.IntegerField(default=0)
    va_eos_in_production = models.IntegerField(default=0)
    
    va_critical_os_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_high_os_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_medium_os_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_low_os_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_critical_nonos_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_high_nonos_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_medium_nonos_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_low_nonos_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_eos_in_tool_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_eos_in_production_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)

    va_critical_os_rs= models.IntegerField(default=0)
    va_high_os_rs= models.IntegerField(default=0)
    va_critical_nonos_rs= models.IntegerField(default=0)
    va_high_nonos_rs= models.IntegerField(default=0)
    va_eos_in_tool_rs= models.IntegerField(default=0)
    va_eos_in_production_rs= models.IntegerField(default=0)

    va_critical_os_rs_justification= models.CharField(max_length=500,default="NA")
    va_high_os_rs_justificaion= models.CharField(max_length=500,default="NA")
    va_critical_nonos_rs_justification= models.CharField(max_length=500,default="NA")
    va_high_nonos_rs_justification= models.CharField(max_length=500,default="NA")
    va_eos_in_tool_rs_justification= models.CharField(max_length=500,default="NA")
    va_eos_in_production_rs_justification= models.CharField(max_length=500,default="NA")


    va_os_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_nonos_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_eos_final_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    va_eos_production_final_rs = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)


    Evidence =  models.CharField(max_length=500,default=None)
  

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"VAPT report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class UER(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    uer_count = models.IntegerField(default=0)
    rbac_count = models.IntegerField(default=0)

    uer_per = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    uer_rs = models.IntegerField(default=0)

    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"UER Report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"
    

#SOC 
class SOCOS(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    #OS
    windows = models.IntegerField(default=0)
    linux = models.IntegerField(default=0)
    os_Evidence =  models.CharField(max_length=500,default=None)

    class Meta:
        verbose_name = "SOC OS"
      

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"SOC - OS {local_date.strftime('%Y-%m-%d %I:%M %p')}"    
   

class SOC_Internal(models.Model):
    date = models.DateTimeField(auto_now_add=True)  
    #Internal 
    internal_total = models.IntegerField(default=0)
    crtitical_open = models.IntegerField(default=0)
    critical_identifies = models.IntegerField(default=0)
    crtitical_open_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    critical_identifies_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    critical_open_risk_score = models.IntegerField(default=0)
    critical_identifies_risk_score = models.IntegerField(default=0)
    critical_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    critical_open_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "SOC Internal"
      

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"SOC - Internal {local_date.strftime('%Y-%m-%d %I:%M %p')}"

    
class SOC_External(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    #External
    external = models.IntegerField(default=0)
    critical_and_high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    low = models.IntegerField(default=0)
    critical_and_high_open = models.IntegerField(default=0)
    medium_open = models.IntegerField(default=0)
    critical_and_high_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    critical_and_high_open_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    critical_and_high_rs = models.IntegerField(default=0)
    critical_and_high_open_rs = models.IntegerField(default=0)
    critical_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    critical_open_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "SOC External"
      


    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"SOC - External {local_date.strftime('%Y-%m-%d %I:%M %p')}"
    

class NAC(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    nac_installed = models.IntegerField(default=0)
    nac_uninstalled = models.IntegerField(default=0)
    nac_unhealthy = models.IntegerField(default=0)
    nac_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    nac_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    nac_uninstalled_risk_score = models.IntegerField(default=0)
    nac_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)


    class Meta:
        verbose_name = "NAC"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"NAC {local_date.strftime('%Y-%m-%d %I:%M %p')}"
 

#APT  Fireeye HX User System now Sentinel
class Sentinel(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    apt_installed = models.IntegerField(default=0)
    apt_uninstalled = models.IntegerField(default=0)
    apt_unhealthy = models.IntegerField(default=0)
    apt_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    apt_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    apt_uninstalled_risk_score = models.IntegerField(default=0)
    apt_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)


    class Meta:
        verbose_name = "Sentinel"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Sentinel {local_date.strftime('%Y-%m-%d %I:%M %p')}"
   

#McAffe Proxy
class McAfee(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    mcafee_installed = models.IntegerField(default=0)
    mcafee_uninstalled = models.IntegerField(default=0)
    mcafee_unhealthy = models.IntegerField(default=0)
    mcafee_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    mcafee_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    mcafee_uninstalled_risk_score = models.IntegerField(default=0)
    mcafee_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)



    class Meta:
        verbose_name = "McAfee Proxy"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"McAfee {local_date.strftime('%Y-%m-%d %I:%M %p')}"
 


class CB(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    cb_installed = models.IntegerField(default=0)
    cb_uninstalled = models.IntegerField(default=0)
    cb_unhealthy = models.IntegerField(default=0)
    cb_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    cb_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    cb_uninstalled_risk_score = models.IntegerField(default=0)
    cb_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)



    class Meta:
        verbose_name = "CB"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"CB {local_date.strftime('%Y-%m-%d %I:%M %p')}"
   

#Forcepoint DLP
class DLP(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    dlp_installed = models.IntegerField(default=0)
    dlp_uninstalled = models.IntegerField(default=0)
    dlp_unhealthy = models.IntegerField(default=0)
    dlp_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    dlp_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    dlp_uninstalled_risk_score = models.IntegerField(default=0)
    dlp_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

  


    class Meta:
        verbose_name = "DLP"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"DLP {local_date.strftime('%Y-%m-%d %I:%M %p')}"
   


class HX(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    hx_installed = models.IntegerField(default=0)
    hx_uninstalled = models.IntegerField(default=0)
    hx_unhealthy = models.IntegerField(default=0)
    hx_uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    hx_unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    hx_uninstalled_risk_score = models.IntegerField(default=0)
    hx_unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "HX"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"HX {local_date.strftime('%Y-%m-%d %I:%M %p')}"
   

class DrDrill(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    drills_Total = models.IntegerField(default=0)
    drills_Unsuccessful = models.IntegerField(default=0)
    drills_NotPerformed = models.IntegerField(default=0)
    drills_Unplanned = models.IntegerField(default=0)
    drills_Unplanned_Unsuccessful = models.IntegerField(default=0)
    drills_Actual_Dr_Invocation = models.IntegerField(default=0)
    drill_Actual_Dr_Invocation_Not_Successful = models.IntegerField(default=0)
    drills_Rollback = models.IntegerField(default=0)
    gaps_identified = models.IntegerField(default=0)
    gaps_Not_Addressed= models.IntegerField(default=0)
    drills_Breached_RTO = models.IntegerField(default=0)
    
    drills_NotPerformed_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    drills_Unplanned_Unsuccessful_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    drills_Unsuccessful_per= models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    drills_Rollback_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    learnings_Not_Address_per= models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    drills_Breached_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)

    drills_NotPerformed_rs =  models.IntegerField(default=0)
    drills_Unplanned_Unsuccessful_rs =  models.IntegerField(default=0)
    drills_Unsuccessful_rs= models.IntegerField(default=0)
    drills_Rollback_rs =  models.IntegerField(default=0)
    learnings_Not_Address_rs=  models.IntegerField(default=0)
    drills_Breached_rs =  models.IntegerField(default=0)

    drills_NotPerformed_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    drills_Unplanned_Unsuccessful_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    drills_Unsuccessful_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    drills_Rollback_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    learnings_Not_Address_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    drills_Breached_Justification=models.CharField(max_length=500,default="NA",null=True, blank=True)


    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)


    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"DR Drill {local_date.strftime('%Y-%m-%d %I:%M %p')}"

 

class Infra(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "VDI Fireye"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"VDI Fireye {local_date.strftime('%Y-%m-%d %I:%M %p')}"
    

#Endpoint Infra 
class McAfeeAVUser(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "McAfeeAVUser"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"McAfeeAVUser {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class McAfeeAVServer(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "McAfeeAVServer"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"McAfeeAVServer {local_date.strftime('%Y-%m-%d %I:%M %p')}"

#McAfee DLP
class McAfeeDLP(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "McAfeeDLP"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"McAfeeDLP {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class Encryption(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "Encryption"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Encryption {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class SecurityAudit(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    total = models.IntegerField(default=0)
    critical = models.IntegerField(default=0)
    high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    low = models.IntegerField(default=0)

    critical_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    medium_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    low_Percentage = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)

    risk_score = models.IntegerField(default=0)
   
    critical_Justification= models.CharField(max_length=500,default="NA",null=True, blank=True)
   
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

  
    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Security Audit report for {local_date.strftime('%Y-%m-%d %I:%M %p')}"


#Asset Mangement 
class AssetManagment(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    class Meta:
        verbose_name = "Asset Managment"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Asset Managment {local_date.strftime('%Y-%m-%d %I:%M %p')}"



#Network
class Network(models.Model):

    date = models.DateTimeField(auto_now_add=True)
    Total = models.IntegerField(default=0)
    critical_and_high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    n_mius_2_os = models.IntegerField(default=0)

    critical_and_high_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    medium_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    n_mius_2_os_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)

    critical_and_high_rs = models.IntegerField(default=0)
    medium_rs = models.IntegerField(default=0)
    n_mius_2_os_rs = models.IntegerField(default=0)


    critical_and_high_rs_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    medium_rs_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    n_mius_2_os_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)

    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)


    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Network{local_date.strftime('%Y-%m-%d %I:%M %p')}"


#Network
class AD(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    Total = models.IntegerField(default=0)
    # Laptop = models.IntegerField(default=0)
    # Desktop = models.IntegerField(default=0)

    Total_Laptop = models.IntegerField(default=0)
    Total_Desktop = models.IntegerField(default=0)

    lLaptop = models.IntegerField(default=0)
    lDesktop = models.IntegerField(default=0)
    wLaptop = models.IntegerField(default=0)
    wDesktop = models.IntegerField(default=0)
    mLaptop = models.IntegerField(default=0)
    mDesktop = models.IntegerField(default=0)

    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"AD{local_date.strftime('%Y-%m-%d %I:%M %p')}"



class RAF(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    total = models.IntegerField(default=0)
    high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    low = models.IntegerField(default=0)

    Evidence =  models.CharField(max_length=500,default=None)

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"RAF {local_date.strftime('%Y-%m-%d %I:%M %p')}"


class PatchManage(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    installed = models.IntegerField(default=0)
    uninstalled = models.IntegerField(default=0)
    unhealthy = models.IntegerField(default=0)
    uninstalled_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    unhealthy_per = models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    uninstalled_risk_score = models.IntegerField(default=0)
    unhealthy_risk_score = models.IntegerField(default=0)
    uninstalled_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    unhealthy_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)


    
    class Meta:
        verbose_name = "Patch Management"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Patch Management{local_date.strftime('%Y-%m-%d %I:%M %p')}"


class Patch(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    total=models.IntegerField(default=0)

    windows_cloud=models.IntegerField(default=0)
    non_windows_cloud=models.IntegerField(default=0)
    db_cloud=models.IntegerField(default=0)

    windows_physical=models.IntegerField(default=0)
    nw_physical=models.IntegerField(default=0)
    db_physical=models.IntegerField(default=0)

    w_critical=models.IntegerField(default=0)
    w_medium=models.IntegerField(default=0)
    w_n_mius_2_os=models.IntegerField(default=0)

    nw_critical=models.IntegerField(default=0)
    nw_medium=models.IntegerField(default=0)
    nw_n_os=models.IntegerField(default=0)

    db_critical=models.IntegerField(default=0)
    db_medium=models.IntegerField(default=0)
    db_n_minus_2_os=models.IntegerField(default=0)

    #percentage
    w_critical_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    w_medium_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    w_n_mius_2_os_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)

    nw_critical_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    nw_medium_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    nw_n_os_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)

    db_critical_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    db_medium_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)
    db_n_minus_2_os_per=models.DecimalField(max_digits=5, decimal_places=4 ,default=0.0)

    #Risk Score
    w_critical_rs=models.IntegerField(default=0)
    w_medium_rs=models.IntegerField(default=0)
    w_n_mius_2_os_rs=models.IntegerField(default=0)

    nw_critical_rs=models.IntegerField(default=0)
    nw_medium_rs=models.IntegerField(default=0)
    nw_n_os_rs=models.IntegerField(default=0)

    db_critical_rs=models.IntegerField(default=0)
    db_medium_rs=models.IntegerField(default=0)
    db_n_minus_2_os_rs=models.IntegerField(default=0)

     #justification
    w_critical_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    w_medium_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    w_n_mius_2_os_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)

    nw_critical_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    nw_medium_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    nw_n_os_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)

    db_critical_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    db_medium_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)
    db_n_minus_2_os_justification=models.CharField(max_length=500,default="NA",null=True, blank=True)

    Evidence =  models.CharField(max_length=500,default=None,null=True, blank=True)
    
    class Meta:
        verbose_name = "Patch"

    def __str__(self):
        local_date = timezone.localtime(self.date)
        return f"Patch{local_date.strftime('%Y-%m-%d %I:%M %p')}"
