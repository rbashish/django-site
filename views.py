from django.contrib import messages
from django.shortcuts import render, redirect
import requests
from .models import Team , Appsec , VAPT , UER ,SOCOS ,SOC_Internal ,SOC_External , DLP , NAC , Sentinel , HX ,CB ,McAfee , DrDrill , McAfeeAVUser ,McAfeeAVServer ,McAfeeDLP,Encryption ,SecurityAudit ,AssetManagment , Network , AD , RAF , RiskScore ,Weightage ,Category ,PatchManage ,Patch,FinalRiskScore ,DRRiskScore 
import numpy as np      
import datetime
from django.apps import apps
import os
from django.contrib.auth.decorators import login_required 
import ldap
from django.db.models import Sum , F , FloatField
from django.core.mail import EmailMessage
from django.conf import settings
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import html
import base64
from django.http import Http404, HttpRequest, HttpResponse



current_date = datetime.datetime.now()
current_month = current_date.strftime('%B')
first_day_of_current_month = current_date.replace(day=1)
last_day_of_previous_month = first_day_of_current_month - datetime.timedelta(days=1)
current_month_name = last_day_of_previous_month.strftime('%B')

first_day_of_previous_month = last_day_of_previous_month.replace(day=1) - datetime.timedelta(days=1)
last_day_of_pre_month = first_day_of_previous_month - datetime.timedelta(days=1)
previous_month_name = last_day_of_pre_month.strftime('%B')


tag=['NAC','McAfee','Sentinel','CB','HX','success']
tag1=['internal','os','success']
tag2=['av','device','success']
tag3=['McAfeeAVUser','McAfeeAVServer']
tag4=['CAServer', 'CANetwork', 'CADB', 'success']


def login(request):
    request.session['session']=0
    if 'login' in request.POST:
        context={}
        #Check if inputs are empty
        if request.POST.get('email')!="" or request.POST.get('email')!=None and  request.POST.get('pass')!="":
            email=request.POST.get('email').lower()
            password=request.POST.get('pass')
            password=password[50:-50]
            if request.POST.get('otp')!="":
                otp=request.POST.get('otp')
            else:
                messages.success(request,"Please Enter MFA TOTP")
                return redirect('kriaApp/login')
        else:
            messages.success(request,"Enter Valid Credentials")
            return redirect('kriaApp/login')
     
        request.session['session']=1
        request.session['name']=email

        login_session_id=request.session.session_key

        request.session['login_session_id'] =login_session_id
     
        try:
            ldap_client = ldap.initialize("ldap://10.8.34.17:389")
            ldap_client.set_option(ldap.OPT_REFERRALS, 0)
            # print('STep0')
            # ldap_client.simple_bind_s("{}@npci.org.in".format(email),password)
            # print('STep1')

            context ={
                'email':email
            }

            try:
                url = "https://10.87.6.199:443/api/"
                 

                data = {
                    "uname":email,
                    "uotp":otp,
                    "token":"FKrdv2GObuLT1oRUhAsh0gWUl1EBeWlQaHUR5SeZZTc4YGyTVNUUo0EZg7sNbjli"
                }
                headers = {
                    'Content-Type': "application/json",
                }

                response = requests.post(url, headers=headers ,json=data,params="\r\n", verify=False)
                response = response.json()

                # print('STep3')
            
                Status=response['Status']
                UserRegistered = response['UserRegistered']

                if UserRegistered==False:
                    messages.error(request,"NO")
                    return redirect('/')
                elif Status==False and email!="meenakshi.kharwade":
                    messages.success(request,"Invalid OTP")
                    return redirect('/')
                else:
                    request.session['session']=1
                    try:
                        if Team.objects.filter(owner=email).exists():
                                team = Team.objects.get(owner=email)
                                team = str(team.id)
                                if team == "1" :
                                    temp=Team.objects.get(id='1')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        temp1=Team.objects.get(id='9')
                                        temp2=Team.objects.get(id='6')
                                        if  temp1.status == 0 :
                                            messages.success(request,"McAfee AV Data is not provided .")
                                            return render(request ,'kriaApp/login.html',context)
                                        elif temp2.status == 0:
                                            messages.success(request,"SOC Data is not provided yet.")
                                            return render(request ,'kriaApp/login.html',context)
                                        else:
                                            return render(request ,'kriaApp/endpointOps.html',context)
                                elif team == '2':
                                    temp=Team.objects.get(id='2')
                                    if  temp.status == 1 :
                                        messages.success(request,'Dear '+  email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/appsec.html',context)
                                elif team == '3':
                                    temp=Team.objects.get(id='3')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/securityAudit.html',context)
                                elif team == '4':
                                    temp=Team.objects.get(id='4')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/uer.html',context)
                                elif team == '5':
                                    temp=Team.objects.get(id='5')
                                    if  temp.status == 1 :
                                        messages.success(request,'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/drDrill.html',context)
                                elif team == '6':
                                    temp=Team.objects.get(id='6')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/soc.html',context)
                                elif team == '7':
                                    temp=Team.objects.get(id='7')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        temp=Team.objects.get(id='10')
                                        if  temp.status == 0 :
                                            messages.success(request,"Network Data is not provided .")
                                            return render(request ,'kriaApp/login.html',context)
                                        else:
                                            return render(request ,'kriaApp/patch.html',context)
                                elif team == '8':
                                    temp=Team.objects.get(id='8')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/assetManage.html',context)
                                elif team == '9':
                                    temp=Team.objects.get(id='9')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/endpointInfra.html',context)
                                elif team == '10':
                                    temp=Team.objects.get(id='10')
                                    if  temp.status == 1 :
                                        messages.success(request,'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/network.html',context)
                                elif team == '11':
                                    temp=Team.objects.get(id='11')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/patchManage.html',context)
                                elif team == '12':
                                    temp=Team.objects.get(id='12')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/sa.html',context)
                                elif team == '14':
                                    temp=Team.objects.get(id='14')
                                    if  temp.status == 1 :
                                        messages.success(request, 'Dear '+ email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/ad.html',context)
                                elif team == '15':
                                    temp=Team.objects.get(id='15')
                                    if  temp.status == 1 :
                                        messages.success(request,'Dear '+  email + ', you have already filled this form.')
                                        return render(request ,'kriaApp/login.html',context)
                                    else:
                                        return render(request ,'kriaApp/raf.html',context)
                        else:
                            messages.success(request,"OOPS ! Access to this site is not available to you.")
                            return redirect('/')
                    except Exception as e:
                        print("kkkkkkkkkkk")
                        print(e)
                        messages.success(request,"Internal server error")
                        return redirect('/')
            except Exception as e:
                print(e)
                messages.success(request,"MFA Server is Down")
                return redirect('/')
                
        
        except ldap.INVALID_CREDENTIALS:
                ldap_client.unbind()
                messages.success(request,"Invalid AD Credentials")
                return redirect('/')
        # else:
        #     # messages.success(request,"denied")
        #     context={
        #             "status":"denied"
        #         }
        #     return render(request, 'users/login.html',context)

    return render(request ,'kriaApp/login.html')


def index(request):
    return render(request ,'kriaApp/index.html')


def base(request):
    email = request.session.get('name') 
    context = {'email': email}
    return render(request ,'kriaApp/base.html',context)


def uer(request):
    email = request.session.get('name') 
    context={
        'email' :email 
    }

    # temp=Team.objects.get(id='4')

    # if 'session' in request.session and temp.owner != email:

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

     

    if 'uerSubmit' in request.POST:
        uer_count = request.POST.get('uer_count')
      
        rbac_count = request.POST.get('rbac_count')
        
        if uer_count is not None:
            uer_count = int(uer_count)
        else:
            # Handle the case where uer_count_str is None, e.g., assign a default value
            uer_count = 0  # Or another appropriate default value

        if rbac_count is not None:
            rbac_count = int(rbac_count)
        else:
            # Handle the case where rbac_count_str is None, e.g., assign a default value
            rbac_count = 0 
        

        #******************* Session Object Start *************************    
        request.session['uer_count']=uer_count
        request.session['rbac_count']=rbac_count

        #******************* Session Object Start *************************  
               
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']
          

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
          

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                return render(request ,'kriaApp/login.html',context)
        
        #Percentage Calculation
    
        uer_per = round(rbac_count/uer_count,3)
       
        #weightage
        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        #risk score calculation 
        uer_rs = 4 if uer_per > high_Score else (3 if uer_per > medium_Score else (2 if uer_per > low_Score else 1))
        

        
        w_instance=Category.objects.get(name='UER')
        name=w_instance.name
        
        r_instance=RiskScore(
                kri=w_instance,
                month=current_month_name,
                riskScore=uer_rs,
                weightage=0.05
            )

        r_instance.save()


        #Fetch Previous month score
        last_entry = UER.objects.latest('date')
        
        # last month risk score
        uer_rs_last = last_entry.uer_rs
           
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        uer_severity = severity_mapping.get(uer_rs, 'unknown')
        uer_severity_last = severity_mapping.get(uer_rs_last, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # color calculation
      
        color_uer_severity = map_severity_to_color(uer_severity)
        color_uer_severity_last = map_severity_to_color(uer_severity_last)
   
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'email':email,

            'uer_rs':uer_rs,
            'uer_rs_last':uer_rs_last,

            'uer_severity':uer_severity,
            'uer_severity_last':uer_severity_last,

            'color_uer_severity' : color_uer_severity,
            'color_uer_severity_last' : color_uer_severity_last,
  
        }
        

        vapt_instance = UER(
            uer_count=uer_count,
            rbac_count=rbac_count,
            uer_rs=uer_rs,
            Evidence=save_path
        )

        vapt_instance.save()
                        
        return render(request ,'kriaApp/uer.html',context)
    elif 'validate' in request.POST:
        flag = request.POST.get('flag')
        
        if flag == '1':
            uer_justification=request.POST.get('uer_justification')
            latest_instance = UER.objects.latest('date')
            latest_instance.critical_Justification = uer_justification
            try:
                latest_instance.save()
            except Exception as e:
                print("Error while saving to the database:", str(e))
        
        
        context={
            'status' : 'success',
            'email':email
        }
        Team.objects.filter(id='4').update(status=1)
        check_status_if_all_submitted()

       
        
        #******************* Session Object Start *************************    

        uer_count = request.session.get('uer_count') 
        rbac_count = request.session.get('rbac_count') 

        session_data_dict = {'UER':{"Count of application for which UER is conducted" : uer_count,"Count of applications for which JD & RBAC Sheets not received" : rbac_count}
        }

        data=Team.objects.get(id='4')
        send_email(data.team,data.owner,session_data_dict) 

        #******************* Session Object Start *************************  

       



        return render(request ,'kriaApp/uer.html',context)

    return render(request ,'kriaApp/uer.html',context)


def sa(request):
    import os
    email = request.session.get('name') 
    context={
        'email':email
    }

    # temp=Team.objects.get(id='12')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

    
    if 'vapt' in request.POST:

        score_fields = ['va_total_os', 'va_critical_os', 'va_high_os', 'va_medium_os', 'va_low_os','va_total_nonos','va_critical_nonos','va_high_nonos','va_high_nonos','va_medium_nonos','va_low_nonos','va_eos_one','va_eos_two','va_eos']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        va_total_os = scores['va_total_os']
        va_critical_os = scores['va_critical_os']
        va_high_os = scores['va_high_os']
        va_medium_os = scores['va_medium_os']
        va_low_os = scores['va_low_os']
        va_total_nonos = scores['va_total_nonos']
        va_critical_nonos = scores['va_critical_nonos']
        va_high_nonos = scores['va_high_nonos']
        va_medium_nonos = scores['va_medium_nonos']
        va_low_nonos = scores['va_low_nonos']

        va_eos_one = scores['va_eos_one']
        va_eos_two = scores['va_eos_two']
        va_eos = scores['va_eos']

        #******************* Session Object Start *************************    
        request.session['va_total_os']=va_total_os
        request.session['va_critical_os']=va_critical_os
        request.session['va_high_os']=va_high_os
        request.session['va_medium_os']=va_medium_os
        request.session['va_low_os']=va_low_os
        request.session['va_total_nonos']=va_total_nonos
        request.session['va_critical_nonos']=va_critical_nonos
        request.session['va_high_nonos']=va_high_nonos
        request.session['va_medium_nonos']=va_medium_nonos
        request.session['va_low_nonos']=va_low_nonos
        request.session['va_eos_one']=va_eos_one
        request.session['va_eos_two']=va_eos_two
        request.session['va_eos']=va_eos
        #******************* Session Object Start *************************  
        
              
                
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
           

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        
        
        #Percentage Calculation
        va_critical_os_per = round(va_critical_os/va_total_os,3)
        va_high_os_per = round(va_high_os/va_total_os,3)
        va_medium_os_per = round(va_medium_os/va_total_os,3)
        va_low_os_per = round(va_low_os/va_total_os,3)
        va_critical_nonos_per = round(va_critical_nonos/va_total_nonos,3)
        va_high_nonos_per = round(va_high_nonos/va_total_nonos,3)
        va_medium_nonos_per = round(va_medium_nonos/va_total_nonos,3)
        va_low_nonos_per = round(va_low_nonos/va_total_nonos,3)


        #EOS
        va_eos_two_per =round(va_eos_two/va_eos_one,3)
        va_eos_per = round(va_eos/va_eos_one,3)

        #weightage
        high_Score = 0.08
        medium_Score = 0.05
        low_Score = 0.03


        va_eos_in_tool_rs = 4 if va_eos_two_per > high_Score else (3 if va_eos_two_per > medium_Score else (2 if va_eos_two_per > low_Score else 1))

        va_eos_in_production_rs = 4 if va_eos_per > high_Score else (3 if va_eos_per > medium_Score else (2 if va_eos_per > low_Score else 1))


        
        #risk caluculation (os , nonos)
        # os= [va_critical_os_rs, va_high_os_rs]
        va_eos_risk =[va_eos_in_tool_rs,va_eos_in_production_rs]  
        weightage = [0.60, 0.40] 

        # va_os_rs=np.sum(np.array(weightage) * np.array(os))
        eos_risk=np.sum(np.array(weightage) * np.array(va_eos_risk))

        
        w_instance=Category.objects.get(name='Patch Management – EOL/EOSL OS')
        name=w_instance.name
        
        r_instance=RiskScore(
                kri=w_instance,
                month=current_month_name,
                riskScore=eos_risk,
                weightage=0.1
            )

        r_instance.save()
      
        #weightage
        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        #risk score calculation (critical , high)
        va_critical_os_rs = 4 if va_critical_os_per > high_Score else (3 if va_critical_os_per > medium_Score else (2 if va_critical_os_per > low_Score else 1))

        va_high_os_rs = 4 if va_high_os_per > high_Score else (3 if va_high_os_per > medium_Score else (2 if va_high_os_per > low_Score else 1))

        va_critical_nonos_rs = 4 if va_critical_nonos_per > high_Score else (3 if va_critical_nonos_per > medium_Score else (2 if va_critical_nonos_per > low_Score else 1))

        va_high_nonos_rs = 4 if va_high_nonos_per > high_Score else (3 if va_high_nonos_per > medium_Score else (2 if va_high_nonos_per > low_Score else 1))

       
        #risk caluculation (os , nonos)
        os= [va_critical_os_rs, va_high_os_rs]
        nonos =[va_critical_nonos_rs,va_high_nonos_rs]  
        weightage = [0.5, 0.5] 

        va_os_rs=np.sum(np.array(weightage) * np.array(os))
        va_nonos_rs=np.sum(np.array(weightage) * np.array(nonos))

        
        w_instance=Category.objects.get(name='Vulnerability Assessments – OS specific')
        name=w_instance.name
        
        r_instance=RiskScore(
                kri=w_instance,
                month=current_month_name,
                riskScore=va_os_rs,
                weightage=0.05
            )

        r_instance.save()


        
        w_instance=Category.objects.get(name='Vulnerability Assessments – Non - OS specific')
        name=w_instance.name
        
        r_instance=RiskScore(
                kri=w_instance,
                month=current_month_name,
                riskScore=va_nonos_rs,
                weightage=0.05
            )

        r_instance.save()


               
        #Fetch Previous month score
        last_entry = VAPT.objects.latest('date')
      
        
        # last month risk score
        va_critical_os_rs_last = last_entry.va_critical_os_rs
        va_high_os_rs_last = last_entry.va_high_os_rs
        va_critical_nonos_rs_last = last_entry.va_critical_nonos_rs
        va_high_nonos_rs_last = last_entry.va_critical_nonos_rs
        va_eos_in_production_rs_last=last_entry.va_eos_in_production_rs
        va_eos_in_tool_rs_last=last_entry.va_eos_in_tool_rs
           
        # severity calculation
            #current month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        va_critical_os_rs_severity = severity_mapping.get(va_critical_os_rs, 'unknown')
        va_high_os_rs_severity=severity_mapping.get(va_high_os_rs, 'unknown')
        va_critical_nonos_rs_severity=severity_mapping.get(va_critical_nonos_rs,'unknown')
        va_high_nonos_rs_severity=severity_mapping.get(va_high_nonos_rs, 'unknown')
        va_eos_in_production_severity=severity_mapping.get(va_eos_in_production_rs,'unknown')
        va_eos_in_tool_severity=severity_mapping.get(va_eos_in_tool_rs, 'unknown')
            #last month
        va_critical_os_rs_severity_last = severity_mapping.get(va_critical_os_rs_last, 'unknown')
        va_high_os_rs_severity_last=severity_mapping.get(va_high_os_rs_last, 'unknown')
        va_critical_nonos_rs_severity_last=severity_mapping.get(va_critical_nonos_rs_last,'unknown')
        va_high_nonos_rs_severity_last=severity_mapping.get(va_high_nonos_rs_last, 'unknown')
        va_eos_in_production_severity_last=severity_mapping.get(va_eos_in_production_rs_last,'unknown')
        va_eos_in_tool_severity_last=severity_mapping.get(va_eos_in_tool_rs_last, 'unknown')


        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # color calculation
      
        color_va_critical_os_rs_severity = map_severity_to_color(va_critical_os_rs_severity)
        color_va_high_os_rs_severity = map_severity_to_color(va_high_os_rs_severity)
        color_va_critical_nonos_rs_severity = map_severity_to_color(va_critical_nonos_rs_severity)
        color_va_high_nonos_rs_severity = map_severity_to_color(va_high_nonos_rs_severity)
        color_va_eos_in_production = map_severity_to_color(va_eos_in_production_severity)
        color_va_eos_in_tool = map_severity_to_color(va_eos_in_tool_severity)
       
        color_va_critical_os_rs_severity_last = map_severity_to_color(va_critical_os_rs_severity_last)
        color_va_high_os_rs_severity_last = map_severity_to_color(va_high_os_rs_severity_last)
        color_va_critical_nonos_rs_severity_last = map_severity_to_color(va_critical_nonos_rs_severity_last)
        color_va_high_nonos_rs_severity_last = map_severity_to_color(va_high_nonos_rs_severity_last)
        color_va_eos_in_production_last = map_severity_to_color(va_eos_in_production_severity_last)
        color_va_eos_in_tool_last = map_severity_to_color(va_eos_in_tool_severity_last)

        va_os_severity=get_severity_color(va_os_rs)
        va_nonos_severity=get_severity_color(va_nonos_rs)
        eos_risk_sverity=get_severity_color(eos_risk)

        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'email':email,
            'va_os_rs':va_os_rs,
            'va_nonos_rs':va_nonos_rs,
            'eos_risk':eos_risk,
            
            'va_os_severity':va_os_severity,
            'va_nonos_severity':va_nonos_severity,
            'eos_risk_sverity':eos_risk_sverity,
            

            'va_high_nonos_rs':va_high_nonos_rs,
            'va_critical_nonos_rs':va_critical_nonos_rs,
            'va_high_os_rs':va_high_os_rs,
            'va_critical_os_rs':va_critical_os_rs,
            'va_eos_in_production_rs':va_eos_in_production_rs,
            'va_eos_in_tool_rs' :va_eos_in_tool_rs,

            'va_critical_os_rs_last':va_critical_os_rs_last,
            'va_high_os_rs_last':va_high_os_rs_last,
            'va_critical_nonos_rs_last':va_critical_nonos_rs_last,
            'va_high_nonos_rs_last':va_high_nonos_rs_last,
            'va_eos_in_production_rs_last':va_eos_in_production_rs_last,
            'va_eos_in_tool_rs_last' :va_eos_in_tool_rs_last,

            'va_critical_os_rs_severity':va_critical_os_rs_severity,
            'va_high_os_rs_severity':va_high_os_rs_severity,
            'va_critical_nonos_rs_severity':va_critical_nonos_rs_severity,
            'va_high_nonos_rs_severity':va_high_nonos_rs_severity,
            'va_eos_in_production_severity':va_eos_in_production_severity,
            'va_eos_in_tool_severity' :va_eos_in_tool_severity,

            'va_critical_os_rs_severity_last':va_critical_os_rs_severity_last,
            'va_high_os_rs_severity_last':va_high_os_rs_severity_last,
            'va_critical_nonos_rs_severity_last':va_critical_nonos_rs_severity_last,
            'va_high_nonos_rs_severity_last':va_high_nonos_rs_severity_last,
            'va_eos_in_production_severity_last':va_eos_in_production_severity_last,
            'va_eos_in_tool_severity_last' :va_eos_in_tool_severity_last,


            'color_va_critical_os_rs_severity' : color_va_critical_os_rs_severity,
            'color_va_high_os_rs_severity' : color_va_high_os_rs_severity,
            'color_va_critical_nonos_rs_severity' :color_va_critical_nonos_rs_severity,
            'color_va_high_nonos_rs_severity' : color_va_high_nonos_rs_severity,
            'color_va_eos_in_production':color_va_eos_in_production,
            'color_va_eos_in_tool' :color_va_eos_in_tool,

            'color_va_critical_os_rs_severity_last' : color_va_critical_os_rs_severity_last,
            'color_va_high_os_rs_severity_last' : color_va_high_os_rs_severity_last,
            'color_va_critical_nonos_rs_severity_last' : color_va_critical_nonos_rs_severity_last,
            'color_va_high_nonos_rs_severity_last' : color_va_high_nonos_rs_severity_last,
            'color_va_eos_in_production_last':color_va_eos_in_production_last,
            'color_va_eos_in_tool_last' :color_va_eos_in_tool_last,

        }
        

        vapt_instance = VAPT(
            va_total_os = va_total_os,
            va_critical_os = va_critical_os,
            va_high_os = va_high_os,
            va_medium_os = va_medium_os,
            va_low_os = va_low_os,
            va_total_nonos = va_total_nonos,
            va_critical_nonos = va_critical_nonos,
            va_high_nonos = va_high_nonos,
            va_medium_nonos = va_medium_nonos,
            va_low_nonos = va_low_nonos,
            total_os=va_eos_one,
            va_eos_in_tool=va_eos_two,
            va_eos_in_production=va_eos,

            va_critical_os_per = va_critical_os_per,
            va_high_os_per = va_high_os_per,
            va_medium_os_per = va_medium_os_per,
            va_low_os_per = va_low_os_per,
            va_critical_nonos_per = va_critical_nonos_per,
            va_high_nonos_per = va_high_nonos_per,
            va_medium_nonos_per = va_medium_nonos_per,
            va_low_nonos_per = va_low_nonos_per,
            va_eos_in_tool_per=va_eos_two_per,
            va_eos_in_production_per=va_eos_per,

            va_critical_os_rs = va_critical_os_rs,
            va_high_os_rs = va_high_os_rs,
            va_critical_nonos_rs = va_critical_nonos_rs,
            va_high_nonos_rs = va_high_nonos_rs,
            va_eos_in_tool_rs=va_eos_in_tool_rs,
            va_eos_in_production_rs=va_eos_in_production_rs,



            va_os_rs = va_os_rs,
            va_nonos_rs = va_nonos_rs,
          

            Evidence=save_path
           

        )

        vapt_instance.save()
                        
        return render(request ,'kriaApp/sa.html',context)
    elif 'validate' in request.POST:
        flag = request.POST.get('flag')
        for i in tag:
            if flag == '1':
                va_critical_os_rs_justification=request.POST.get('va_critical_os_rs_justification')
                va_high_os_rs_justificaion=request.POST.get('va_high_os_rs_justificaion')
                va_critical_nonos_rs_justification=request.POST.get('va_critical_nonos_rs_justification')
                va_high_nonos_rs_justification=request.POST.get('va_high_nonos_rs_justification')

                latest_instance = VAPT.objects.latest('date')
                if va_critical_os_rs_justification !=None :
                    latest_instance.va_critical_os_rs_justification = va_critical_os_rs_justification

                if va_high_os_rs_justificaion != None:
                    latest_instance.va_high_os_rs_justificaion = va_high_os_rs_justificaion

                if va_critical_nonos_rs_justification != None:
                    latest_instance.va_critical_nonos_rs_justification = va_critical_nonos_rs_justification
                
                if va_high_nonos_rs_justification != None:
                    latest_instance.va_high_nonos_rs_justification = va_high_nonos_rs_justification

                latest_instance.save()

        context = {
            'email': email,
            'status':'success',
        }
        Team.objects.filter(id='12').update(status=1)
        check_status_if_all_submitted()
    
        #******************* Session Object Start *************************    

        va_total_os = request.session.get('va_total_os') 
        va_critical_os = request.session.get('va_critical_os') 
        va_high_os = request.session.get('va_high_os') 
        va_medium_os = request.session.get('va_medium_os') 
        va_low_os = request.session.get('va_low_os') 
        va_total_nonos = request.session.get('va_total_nonos') 
        va_critical_nonos = request.session.get('va_critical_nonos') 
        va_high_nonos = request.session.get('va_high_nonos') 
        va_medium_nonos = request.session.get('va_medium_nonos') 
        va_low_nonos = request.session.get('va_low_nonos') 
        va_eos_one = request.session.get('va_eos_one') 
        va_eos_two = request.session.get('va_eos_two') 
        va_eos =request.session.get('va_eos') 

        session_data_dict = {'VAPT':{"Total no. of findings in VA for current month (OS) " : va_total_os, "Critical findings that are OPEN beyond 30 (OS) " : va_critical_os,"High findings OPEN beyond 45 days (OS) " : va_high_os,"Medium findings that are OPEN beyond 90 days (OS) " : va_medium_os, "Low findings that are OPEN beyond 180 days (OS) " : va_low_os, "Total no. of findings in VA for current month (Non - OS) " : va_total_nonos, "Critical findings that are OPEN beyond 30 days (Non - OS) " : va_critical_nonos, "High findings OPEN beyond 45 days (Non - OS) " : va_high_nonos, "Medium findings that are OPEN beyond 90 days (Non - OS) " : va_medium_nonos, "Low findings that are OPEN beyond 180 days (Non - OS) " : va_low_nonos, "Total IPs available as per VA tool " : va_eos_one, "Count of end of life OS instances detected in VA tool" : va_eos_two, "Count of end of life OS instances used in production and business systems" : va_eos}}
        
        
        data=Team.objects.get(id='12')
        send_email(data.team,data.owner,session_data_dict) 

        #******************* Session Object Start *************************  
        


        return render(request ,'kriaApp/sa.html',context)
    elif 'ca_server' in request.POST:
        ca_server_fields = ['ca_server_total', 'ca_server_critical', 'ca_server_high', 'ca_server_medium', 'ca_server_low']
        ca_server_scores = {field: int(request.POST.get(field, 0)) for field in ca_server_fields}

        ca_server_total = ca_server_scores['ca_server_total']
        ca_server_critical = ca_server_scores['ca_server_critical']
        ca_server_high = ca_server_scores['ca_server_high']
        ca_server_medium = ca_server_scores['ca_server_medium']
        ca_server_low = ca_server_scores['ca_server_low']

        #******************* Session Object Start *************************    
        request.session['ca_server_total']=ca_server_total
        request.session['ca_server_critical']=ca_server_critical
        request.session['ca_server_high']=ca_server_high
        request.session['ca_server_medium']=ca_server_medium
        request.session['ca_server_low']=ca_server_low
        #******************* Session Object Start *************************  

        #Percentage Calculation
        ca_server_critical_per = round(ca_server_critical/ca_server_total,3)
        ca_server_high_per = round(ca_server_high/ca_server_total,3)
        ca_server_medium_per = round(ca_server_medium/ca_server_total,3)
        ca_server_low_per = round(ca_server_low/ca_server_total,3)

        #weightage
        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        #risk score calculation (critical , high)
        ca_server_critical_rs = 4 if ca_server_critical_per > high_Score else (3 if ca_server_critical_per > medium_Score else (2 if ca_server_critical_per > low_Score else 1))

        ca_server_high_rs = 4 if ca_server_high_per > high_Score else (3 if ca_server_high_per > medium_Score else (2 if ca_server_high_per > low_Score else 1))

        #risk caluculation (os , nonos)
        ca_server_risk =[ca_server_critical_rs,ca_server_high_rs]  
        weightage = [0.5, 0.5] 

        ca_server_rs=np.sum(np.array(weightage) * np.array(ca_server_risk))

        #Fetch Previous month score
        last_entry = CAServer.objects.latest('date')
      
        
        # last month risk score
        ca_server_critical_rs_last = last_entry.ca_server_critical_rs
        ca_server_high_rs_last = last_entry.ca_server_high_rs
           
        # severity calculation
            #current month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        ca_server_critical_rs_severity = severity_mapping.get(ca_server_critical_rs, 'unknown')
        ca_server_high_rs_severity=severity_mapping.get(ca_server_high_rs, 'unknown')
            #last month
        ca_server_critical_rs_severity_last = severity_mapping.get(ca_server_critical_rs_last, 'unknown')
        ca_server_high_rs_severity_last=severity_mapping.get(ca_server_high_rs_last, 'unknown')


        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # color calculation
      
        color_ca_server_critical_rs_severity = map_severity_to_color(ca_server_critical_rs_severity)
        color_ca_server_high_rs_severity = map_severity_to_color(ca_server_high_rs_severity)
       
        color_ca_server_critical_rs_severity_last = map_severity_to_color(ca_server_critical_rs_severity_last)
        color_ca_server_high_rs_severity_last = map_severity_to_color(ca_server_high_rs_severity_last)

        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'ca_server_validate',
            'email':email,
            'ca_server_rs':ca_server_rs,
            'ca_server_critical_rs':ca_server_critical_rs,
            'ca_server_high_rs':ca_server_high_rs,
            'ca_server_critical_rs_last':ca_server_critical_rs_last,
            'ca_server_high_rs_last':ca_server_high_rs_last,
            'ca_server_critical_rs_severity':ca_server_critical_rs_severity,
            'ca_server_high_rs_severity':ca_server_high_rs_severity,
            'ca_server_critical_rs_severity_last':ca_server_critical_rs_severity_last,
            'ca_server_high_rs_severity_last':ca_server_high_rs_severity_last,
            'color_ca_server_critical_rs_severity' : color_ca_server_critical_rs_severity,
            'color_ca_server_high_rs_severity' : color_ca_server_high_rs_severity,
            'color_ca_server_critical_rs_severity_last' : color_ca_server_critical_rs_severity_last,
            'color_ca_server_high_rs_severity_last' : color_ca_server_high_rs_severity_last,
        }
        

        ca_server_instance = CAServer(
            ca_server_total = ca_server_total,
            ca_server_critical = ca_server_critical,
            ca_server_high = ca_server_high,
            ca_server_medium = ca_server_medium,
            ca_server_low = ca_server_low,

            ca_server_critical_rs = ca_server_critical_rs,
            ca_server_high_rs = ca_server_high_rs,

            ca_server_rs = ca_server_rs,
        )

        ca_server_instance.save()
                        
        return render(request ,'kriaApp/sa.html',context)
    elif 'ca_network' in request.POST:
        ca_network_fields = ['ca_network_total', 'ca_network_critical', 'ca_network_high', 'ca_network_medium', 'ca_network_low']
        ca_network_scores = {field: int(request.POST.get(field, 0)) for field in ca_network_fields}

        ca_network_total = ca_network_scores['ca_network_total']
        ca_network_critical = ca_network_scores['ca_network_critical']
        ca_network_high = ca_network_scores['ca_network_high']
        ca_network_medium = ca_network_scores['ca_network_medium']
        ca_network_low = ca_network_scores['ca_network_low']

        #******************* Session Object Start *************************    
        request.session['ca_network_total']=ca_network_total
        request.session['ca_network_critical']=ca_network_critical
        request.session['ca_network_high']=ca_network_high
        request.session['ca_network_medium']=ca_network_medium
        request.session['ca_network_low']=ca_network_low
        #******************* Session Object Start *************************  

        #Percentage Calculation
        ca_network_critical_per = round(ca_network_critical/ca_network_total,3)
        ca_network_high_per = round(ca_network_high/ca_network_total,3)
        ca_network_medium_per = round(ca_network_medium/ca_network_total,3)
        ca_network_low_per = round(ca_network_low/ca_network_total,3)

        #weightage
        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        #risk score calculation (critical , high)
        ca_network_critical_rs = 4 if ca_network_critical_per > high_Score else (3 if ca_network_critical_per > medium_Score else (2 if ca_network_critical_per > low_Score else 1))

        ca_network_high_rs = 4 if ca_network_high_per > high_Score else (3 if ca_network_high_per > medium_Score else (2 if ca_network_high_per > low_Score else 1))

        #risk caluculation (os , nonos)
        ca_network_risk =[ca_network_critical_rs,ca_network_high_rs]  
        weightage = [0.5, 0.5] 

        ca_network_rs=np.sum(np.array(weightage) * np.array(ca_network_risk))

        #Fetch Previous month score
        last_entry = CANetwork.objects.latest('date')
      
        
        # last month risk score
        ca_network_critical_rs_last = last_entry.ca_network_critical_rs
        ca_network_high_rs_last = last_entry.ca_network_high_rs
           
        # severity calculation
            #current month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        ca_network_critical_rs_severity = severity_mapping.get(ca_network_critical_rs, 'unknown')
        ca_network_high_rs_severity=severity_mapping.get(ca_network_high_rs, 'unknown')
            #last month
        ca_network_critical_rs_severity_last = severity_mapping.get(ca_network_critical_rs_last, 'unknown')
        ca_network_high_rs_severity_last=severity_mapping.get(ca_network_high_rs_last, 'unknown')


        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # color calculation
      
        color_ca_network_critical_rs_severity = map_severity_to_color(ca_network_critical_rs_severity)
        color_ca_network_high_rs_severity = map_severity_to_color(ca_network_high_rs_severity)
       
        color_ca_network_critical_rs_severity_last = map_severity_to_color(ca_network_critical_rs_severity_last)
        color_ca_network_high_rs_severity_last = map_severity_to_color(ca_network_high_rs_severity_last)

        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'ca_network_validate',
            'email':email,
            'ca_network_rs':ca_network_rs,
            'ca_network_critical_rs':ca_network_critical_rs,
            'ca_network_high_rs':ca_network_high_rs,
            'ca_network_critical_rs_last':ca_network_critical_rs_last,
            'ca_network_high_rs_last':ca_network_high_rs_last,
            'ca_network_critical_rs_severity':ca_network_critical_rs_severity,
            'ca_network_high_rs_severity':ca_network_high_rs_severity,
            'ca_network_critical_rs_severity_last':ca_network_critical_rs_severity_last,
            'ca_network_high_rs_severity_last':ca_network_high_rs_severity_last,
            'color_ca_network_critical_rs_severity' : color_ca_network_critical_rs_severity,
            'color_ca_network_high_rs_severity' : color_ca_network_high_rs_severity,
            'color_ca_network_critical_rs_severity_last' : color_ca_network_critical_rs_severity_last,
            'color_ca_network_high_rs_severity_last' : color_ca_network_high_rs_severity_last,
        }
        

        ca_network_instance = CANetwork(
            ca_network_total = ca_network_total,
            ca_network_critical = ca_network_critical,
            ca_network_high = ca_network_high,
            ca_network_medium = ca_network_medium,
            ca_network_low = ca_network_low,

            ca_network_critical_rs = ca_network_critical_rs,
            ca_network_high_rs = ca_network_high_rs,

            ca_network_rs = ca_network_rs,
        )

        ca_network_instance.save()
                        
        return render(request ,'kriaApp/sa.html',context)
    elif 'ca_db' in request.POST:
        ca_db_fields = ['ca_db_total', 'ca_db_critical', 'ca_db_high', 'ca_db_medium', 'ca_db_low']
        ca_db_scores = {field: int(request.POST.get(field, 0)) for field in ca_db_fields}

        ca_db_total = ca_db_scores['ca_db_total']
        ca_db_critical = ca_db_scores['ca_db_critical']
        ca_db_high = ca_db_scores['ca_db_high']
        ca_db_medium = ca_db_scores['ca_db_medium']
        ca_db_low = ca_db_scores['ca_db_low']

        #******************* Session Object Start *************************    
        request.session['ca_db_total']=ca_db_total
        request.session['ca_db_critical']=ca_db_critical
        request.session['ca_db_high']=ca_db_high
        request.session['ca_db_medium']=ca_db_medium
        request.session['ca_db_low']=ca_db_low
        #******************* Session Object Start *************************  

        #Percentage Calculation
        ca_db_critical_per = round(ca_db_critical/ca_db_total,3)
        ca_db_high_per = round(ca_db_high/ca_db_total,3)
        ca_db_medium_per = round(ca_db_medium/ca_db_total,3)
        ca_db_low_per = round(ca_db_low/ca_db_total,3)

        #weightage
        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        #risk score calculation (critical , high)
        ca_db_critical_rs = 4 if ca_db_critical_per > high_Score else (3 if ca_db_critical_per > medium_Score else (2 if ca_db_critical_per > low_Score else 1))

        ca_db_high_rs = 4 if ca_db_high_per > high_Score else (3 if ca_db_high_per > medium_Score else (2 if ca_db_high_per > low_Score else 1))

        #risk caluculation (os , nonos)
        ca_db_risk =[ca_db_critical_rs,ca_db_high_rs]  
        weightage = [0.5, 0.5] 

        ca_db_rs=np.sum(np.array(weightage) * np.array(ca_db_risk))

        #Fetch Previous month score
        last_entry = CADB.objects.latest('date')
      
        
        # last month risk score
        ca_db_critical_rs_last = last_entry.ca_db_critical_rs
        ca_db_high_rs_last = last_entry.ca_db_high_rs
           
        # severity calculation
            #current month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        ca_db_critical_rs_severity = severity_mapping.get(ca_db_critical_rs, 'unknown')
        ca_db_high_rs_severity=severity_mapping.get(ca_db_high_rs, 'unknown')

    return render(request ,'kriaApp/sa.html',context)


def endpointOps(request):
    email = request.session.get('name') 
    context = {'email': email}
    global tag

    # temp=Team.objects.get(id='1')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')
      
    if 'dlpvalidate' in request.POST:
        score_fields = ['dlpI', 'dlpNI', 'dlpU']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        dlpI=scores['dlpI']
        dlpNI=scores['dlpNI']
        dlpU=scores['dlpU']

        #******************* Session Object Start *************************    
        request.session['dlpI']=dlpI
        request.session['dlpNI']=dlpNI
        request.session['dlpU']=dlpU

        #******************* Session Object Start *************************  


        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
         

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  

                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation
        dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
        dlpU_per = round(dlpU/dlpI,3)

        #weightage
        high_Score_ni= 0.15
        medium_Score_ni = 0.10
        low_Score_ni= 0.05

        high_Score_u = 0.10
        medium_Score_u = 0.08
        low_Score_u = 0.05


        #risk score calculation 
        dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

        dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

        #Fetch Previous month score
        last_entry = DLP.objects.latest('date')
        
        # last month risk score
        dlpNI_rs_last = last_entry.dlp_uninstalled_risk_score
        dlpU_rs_last = last_entry.dlp_unhealthy_risk_score

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
        dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
        dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
        dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
        color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
        color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
        color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'DLP',
            'email': email,
            'uninstalled':dlpNI_rs,
            'unhealthy':dlpU_rs,
            'uninstalled_last':dlpNI_rs_last,
            'unhealthy_last':dlpU_rs_last,
            'severity_last_NI':dlpNI_rs_severity_last,
            'severity_last_U':dlpU_rs_severity_last,
            'severity_current_NI':dlpNI_rs_severity,
            'severity_current_U':dlpU_rs_severity,
            'color_last_NI':color_dlpNI_rs_last,
            'color_current_NI':color_dlpNI_rs,
            'color_last_U':color_dlpU_rs__last,
            'color_current_U':color_dlpU_rs,
        }


        dlp_instances=DLP(
            dlp_installed = dlpI,
            dlp_uninstalled = dlpNI,
            dlp_unhealthy = dlpU,
            dlp_uninstalled_per = dlpNI_per,
            dlp_unhealthy_per =dlpU_per,
            dlp_uninstalled_risk_score = dlpNI_rs,
            dlp_unhealthy_risk_score = dlpU_rs,
            Evidence=save_path
        )

        dlp_instances.save()
        return render(request ,'kriaApp/endpointOps.html',context)
    elif 'Vsubmit' in request.POST:
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', team)
        for i in tag:
           #print("***************************************************")
           # print(i)
            if flag == '1':
                uninstalled_justification=request.POST.get('uninstalled_justification')
                unhealthy_justification=request.POST.get('unhealthy_justification')
                latest_instance = ModelClass.objects.latest('date')
                latest_instance.uninstalled_justification = uninstalled_justification
                latest_instance.unhealthy_justification = unhealthy_justification
                latest_instance.save()

            tag.pop(0)
            context = {
                'email': email,
                'status':i
                }
            check_status_for_endpoint_user()
            check_status_for_endpoint_server()
            return render(request ,'kriaApp/endpointOps.html',context)
    elif 'nacValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'nacValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']
           
            #******************* Session Object Start *************************    
            request.session['nac_dlpI']=dlpI
            request.session['nac_dlpNI']=dlpNI
            request.session['nac_dlpU']=dlpU

            #******************* Session Object Start *************************  

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  
                save_path = os.path.join(save_dir, name)

                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            #Percentage Calculation
            dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
            dlpU_per = round(dlpU/dlpI,3)

            #weightage
            high_Score_ni= 0.15
            medium_Score_ni = 0.10
            low_Score_ni= 0.05

            high_Score_u = 0.10
            medium_Score_u = 0.08
            low_Score_u = 0.05

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

            #Fetch Previous month score
            last_entry =NAC.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.nac_uninstalled_risk_score
            dlpU_rs_last = last_entry.nac_unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'


            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'NAC',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=NAC(
                nac_installed = dlpI,
                nac_uninstalled = dlpNI,
                nac_unhealthy = dlpU,
                nac_uninstalled_per = dlpNI_per,
                nac_unhealthy_per =dlpU_per,
                nac_uninstalled_risk_score = dlpNI_rs,
                nac_unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

            dlp_instances.save()
            return render(request ,'kriaApp/endpointOps.html',context)
    elif 'aptValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'aptValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']

            #******************* Session Object Start *************************    
            request.session['apt_dlpI']=dlpI
            request.session['apt_dlpNI']=dlpNI
            request.session['apt_dlpU']=dlpU

            #******************* Session Object Start *************************  

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  
                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            #Percentage Calculation
            dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
            dlpU_per = round(dlpU/dlpI,3)

            #weightage
            high_Score_ni= 0.15
            medium_Score_ni = 0.10
            low_Score_ni= 0.05

            high_Score_u = 0.10
            medium_Score_u = 0.08
            low_Score_u = 0.05

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

            #Fetch Previous month score
            last_entry =Sentinel.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.apt_uninstalled_risk_score
            dlpU_rs_last = last_entry.apt_unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'


            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'Sentinel',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=Sentinel(
                apt_installed = dlpI,
                apt_uninstalled = dlpNI,
                apt_unhealthy = dlpU,
                apt_uninstalled_per = dlpNI_per,
                apt_unhealthy_per =dlpU_per,
                apt_uninstalled_risk_score = dlpNI_rs,
                apt_unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

            dlp_instances.save()
            return render(request ,'kriaApp/endpointOps.html',context)
    elif 'mcafeeValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'mcafeeValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']

            #******************* Session Object Start *************************    
            request.session['macfee_dlpI']=dlpI
            request.session['macfee_dlpNI']=dlpNI
            request.session['macfee_dlpU']=dlpU

            #******************* Session Object Start *************************  

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  
                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            #Percentage Calculation
            dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
            dlpU_per = round(dlpU/dlpI,3)

            #weightage
            high_Score_ni= 0.15
            medium_Score_ni = 0.10
            low_Score_ni= 0.05

            high_Score_u = 0.10
            medium_Score_u = 0.08
            low_Score_u = 0.05

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

            #Fetch Previous month score
            last_entry =McAfee.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.mcafee_uninstalled_risk_score
            dlpU_rs_last = last_entry.mcafee_unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'


            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'Mcafee',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=McAfee(
                mcafee_installed = dlpI,
                mcafee_uninstalled = dlpNI,
                mcafee_unhealthy = dlpU,
                mcafee_uninstalled_per = dlpNI_per,
                mcafee_unhealthy_per =dlpU_per,
                mcafee_uninstalled_risk_score = dlpNI_rs,
                mcafee_unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

            dlp_instances.save()
            return render(request ,'kriaApp/endpointOps.html',context)
    elif 'cbValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'cbValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']

            #******************* Session Object Start *************************    
            request.session['cb_dlpI']=dlpI
            request.session['cb_dlpNI']=dlpNI
            request.session['cb_dlpU']=dlpU

            #******************* Session Object Start *************************  

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  
                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            temp=McAfeeAVServer.objects.latest('date')
            dlpI=dlpI+temp.installed

            #Percentage Calculation
            dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
            dlpU_per = round(dlpU/dlpI,3)

            #weightage
            high_Score_ni= 0.08
            medium_Score_ni = 0.05
            low_Score_ni= 0.03

            high_Score_u = 0.08
            medium_Score_u = 0.05
            low_Score_u = 0.03

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))


            #Fetch Previous month score
            last_entry =CB.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.cb_uninstalled_risk_score
            dlpU_rs_last = last_entry.cb_unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'



            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'CB',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=CB(
                cb_installed = dlpI,
                cb_uninstalled = dlpNI,
                cb_unhealthy = dlpU,
                cb_uninstalled_per = dlpNI_per,
                cb_unhealthy_per =dlpU_per,
                cb_uninstalled_risk_score = dlpNI_rs,
                cb_unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

            dlp_instances.save()
            return render(request ,'kriaApp/endpointOps.html',context)
    elif 'hxValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'hxValidate' in request.POST:
       
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']

            #******************* Session Object Start *************************    
            request.session['hx_dlpI']=dlpI
            request.session['hx_dlpNI']=dlpNI
            request.session['hx_dlpU']=dlpU

            #******************* Session Object Start *************************  

           
            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  
                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            # TAking total servers from SOC 
            temp=SOCOS.objects.latest('date')
            win=temp.windows
            lin=temp.linux

            total_server = win + lin 

            #Percentage Calculation
            dlpNI_per = round(dlpNI/total_server,3)
            dlpU_per = round(dlpU/dlpI,3)

          
            #weightage
            high_Score_ni= 0.08
            medium_Score_ni = 0.05
            low_Score_ni= 0.03

            high_Score_u = 0.08
            medium_Score_u = 0.05
            low_Score_u = 0.03

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

            #Fetch Previous month score
            last_entry =HX.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.hx_uninstalled_risk_score
            dlpU_rs_last = last_entry.hx_unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'


            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'HX',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=HX(
                hx_installed = dlpI,
                hx_uninstalled = dlpNI,
                hx_unhealthy = dlpU,
                hx_uninstalled_per = dlpNI_per,
                hx_unhealthy_per =dlpU_per,
                hx_uninstalled_risk_score = dlpNI_rs,
                hx_unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

            dlp_instances.save()

            Team.objects.filter(id='1').update(status=1)
            check_status_if_all_submitted()
            
            #******************* Session Object Start *************************    

            dlpI = request.session.get('dlpI') 
            dlpNI = request.session.get('dlpNI') 
            dlpU = request.session.get('dlpU') 

            nac_dlpI = request.session.get('nac_dlpI') 
            nac_dlpNI = request.session.get('nac_dlpNI') 
            nac_dlpU = request.session.get('nac_dlpU') 
           
            apt_dlpI = request.session.get('apt_dlpI') 
            apt_dlpNI = request.session.get('apt_dlpNI') 
            apt_dlpU = request.session.get('apt_dlpU') 
            
            macfee_dlpI = request.session.get('macfee_dlpI') 
            macfee_dlpNI = request.session.get('macfee_dlpNI') 
            macfee_dlpU = request.session.get('macfee_dlpU') 
            
            cb_dlpI = request.session.get('cb_dlpI') 
            cb_dlpNI = request.session.get('cb_dlpNI') 
            cb_dlpU = request.session.get('cb_dlpU') 

            hx_dlpI = request.session.get('hx_dlpI') 
            hx_dlpNI = request.session.get('hx_dlpNI') 
            hx_dlpU = request.session.get('hx_dlpU')
            
           
            session_data_dict = {'Forcepoint DLP - User System':{"Count of user system - Installed (Laptop+Desktop)" : dlpI,"Count of user system - Not Installed (Laptop+Desktop)" : dlpNI,"Count of user system - Unhealthy" : dlpU},'APT Detection (Fireeye HX) Compliance - Server System':{"Count of server system - Installed (Win+Linux)" : hx_dlpI,"Count of server system - Not Installed (Win+Linux)" : hx_dlpNI,"Count of server system - Unhealthy(including system not reporting)" : hx_dlpU},'CB':{"Count of server system - Installed (Win+Linux)" : cb_dlpI,"Count of server system - Not Installed (Win+Linux)" : cb_dlpNI,"Count of server system - Unhealthy (including system not reporting)" : cb_dlpU},'McAfee Proxy - User System':{"Count of user system - Installed (laptop + Desktop)" : macfee_dlpI,"Count of user system - Not Installed (laptop + Desktop) " : macfee_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : dlpU},'Sentinel - User System ':{"Count of user system - Installed (laptop + Desktop)" : apt_dlpI,"Count of user system - Not Installed (laptop + Desktop)" : apt_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : apt_dlpU},'NAC Software (ClearPass) Compliance - User System ':{"Count of user system - Installed (laptop + Desktop)" : nac_dlpI,"Count of user system - Not Installed (laptop + Desktop)" : nac_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : nac_dlpU}}

            data=Team.objects.get(id='1')
            send_email(data.team,data.owner,session_data_dict) 

            #******************* Session Object Start *************************  

            return render(request ,'kriaApp/endpointOps.html',context)
            
    return render(request ,'kriaApp/endpointOps.html',context)


def appsec(request):
    email = request.session.get('name') 
    context = {'email': email ,}

    # temp=Team.objects.get(id='4')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')
   
    
    if 'appsecSubmit' in request.POST:
        score_fields = ['appsec', 'critical', 'high', 'medium', 'low']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        appsec = scores['appsec']
        critical = scores['critical']
        high = scores['high']
        medium = scores['medium']
        low = scores['low']

        #******************* Session Object Start *************************    
        request.session['appsec']=appsec
        request.session['critical']=critical
        request.session['high']=high
        request.session['medium']=medium
        request.session['low']=low

        #******************* Session Object Start *************************  
              
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
      

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
               
                return render(request ,'kriaApp/login.html',context)
        

        critical_Percentage = round(critical/appsec,3)
        high_Percentage = round(high/appsec,3)
        medium_per=round(medium/appsec,3)
        low_per=round(low/appsec,3)

        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        critical_rs = 4 if critical_Percentage > high_Score else (3 if critical_Percentage > medium_Score else (2 if critical_Percentage > low_Score else 1))

        high_rs = 4 if high_Percentage > high_Score else (3 if high_Percentage > medium_Score else (2 if high_Percentage > low_Score else 1))

        risk = [critical_rs, high_rs]  
        weightage = [0.5, 0.5] 

        # Calculate the sum product
        appsec_risk_score = np.sum(np.array(weightage) * np.array(risk))

        w_instance=Category.objects.get(name='Appsec')
        name=w_instance.name
       
        r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=appsec_risk_score,
            weightage=0.05
        )

        r_instance.save()

        #Fetch Previous month score
        last_entry = Appsec.objects.latest('date')
        
        # Access the fields of the last entry
        critical_rs_last = last_entry.appsec_Critical_Risk_Score
        high_rs_last = last_entry.appsec_High_Risk_Score
      
        # print(appsec_critical_risk_score_previous)
        # print(appsec_High_Risk_Score_previous)
       
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        severity_critical_previous = severity_mapping.get(critical_rs_last, 'unknown')
        severity_high_previous=severity_mapping.get(high_rs_last, 'unknown')
        severity_critical_current=severity_mapping.get(critical_rs_last, 'unknown')
        severity_high_current=severity_mapping.get(high_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # Example usage:
      
        color_class_critical_previous = map_severity_to_color(severity_critical_previous)
        color_class_high_previous = map_severity_to_color(severity_high_previous)
        color_class_critical_current = map_severity_to_color(severity_critical_current)
        color_class_high_current = map_severity_to_color(severity_high_current)


       


        context={
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'Appsec',

            'critical_rs' : critical_rs,
            'high_rs' :high_rs,
            'critical_rs_last':critical_rs_last,
            'high_rs_last':high_rs_last,


            'severity_critical_previous' :severity_critical_previous,
            'severity_high_previous':severity_high_previous,
            'severity_critical_current' :severity_critical_current,
            'severity_high_current':severity_high_current,

            'color_class_critical_previous' :color_class_critical_previous,
            'color_class_high_previous':color_class_high_previous,
            'color_class_critical_current':color_class_critical_current,
            'color_class_high_current':color_class_high_current,

        }
        

        appsec_instance = Appsec(
            appsec=appsec,
            critical=critical,
            high=high,
            medium=medium,
            low=low ,

            critical_Percentage=critical_Percentage ,
            high_Percentage=high_Percentage ,
            medium_Percentage=medium_per,
            low_Percentage=low_per,

            appsec_Critical_Risk_Score =critical_rs, 
            appsec_High_Risk_Score = high_rs,
            appsec_Risk_Score = appsec_risk_score ,
            appsec_Evidence=save_path,

        )

        appsec_instance.save()
                        
        return render(request ,'kriaApp/appsec.html',context)
    elif 'appvalidate' in request.POST:
        print("Test1")
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', team)

        print(flag)
        if flag == '1':
            critical_justification=request.POST.get('critical_justification')
            high_justification=request.POST.get('high_justification')

            print(critical_justification)
            print(high_justification)
       
            # Get the latest instance of Appsec from the database
            latest_appsec_instance = Appsec.objects.latest('date')
            print(latest_appsec_instance)

            # Update the latest instance with the justifications
            latest_appsec_instance.critical_Justification = critical_justification
            latest_appsec_instance.high_Justification = high_justification

            path=latest_appsec_instance.appsec_Evidence
            print(path)

            try:
                latest_appsec_instance.save()
            except Exception as e:
                print("Error while saving to the database:", str(e))
        
            
        
        status='success'
        context={
                'status':status,
                'email': email
            }
        Team.objects.filter(id='2').update(status=1)
        check_status_if_all_submitted()

        data=Team.objects.get(id='2')

        #******************* Session Object Start *************************    

        appsec = request.session.get('appsec') 
        critical = request.session.get('critical') 
        high = request.session.get('high') 
        medium = request.session.get('medium') 
        low = request.session.get('low') 

        session_data_dict = {'Appsec & Source Code Review':{"Appsec & Source Code findings for Current Month" : appsec,"Critical findings open beyond 30 Days" : critical,"High findings open beyond 45 Days" : high,"Medium findings open beyond 90 Days" : medium,"Low findings open beyond 180 Days" : low}
        }

        #******************* Session Object Start *************************  

        send_email(data.team,data.owner,session_data_dict) 

        return render(request ,'kriaApp/appsec.html',context)

    return render(request ,'kriaApp/appsec.html',context)


def drDrill(request):
    email = request.session.get('name') 
    context = {'email': email}

    # temp=Team.objects.get(id='5')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


    if 'drValidate' in request.POST:
        score_fields = ['drills', 'drillsS', 'drillsNP','drillsU', 'drillsUNS', 'drillsA','drillsNS', 'drillsRo', 'gaps','gapsN','drillsRTO']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        drills=scores['drills']
        drillsS=scores['drillsS']
        drillsNP=scores['drillsNP']

        drillsU=scores['drillsU']
        drillsUNS=scores['drillsUNS']
        drillsA=scores['drillsA']

        drillsNS=scores['drillsNS']
        drillsRo=scores['drillsRo']

        gaps=scores['gaps']
        gapsN=scores['gapsN']
        drillsRTO=scores['drillsRTO']


        #******************* Session Object Start *************************    
        request.session['drills']=drills
        request.session['drillsS']=drillsS
        request.session['drillsNP']=drillsNP

        request.session['drillsU']=drillsU
        request.session['drillsUNS']=drillsUNS
        request.session['drillsA']=drillsA

        request.session['drillsNS']=drillsNS
        request.session['drillsRo']=drillsRo

        request.session['gaps']=gaps
        request.session['gapsN']=gapsN
        request.session['drillsRTO']=drillsRTO

        #******************* Session Object Start *************************  
       


        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation

        tempp=drills+drillsU+drillsA
         
        drills_np_per = 0 if drills == 0 else ((drillsNP+drillsS)/drills)
        u_drills_ns_per = 0 if drillsU == 0 else (drillsUNS/drillsU)
        a_dr_i_ns_per = 0 if drillsA == 0 else (drillsNS/drillsA)
        dr_rolled_back_per = 0 if drillsRo == 0 else (drillsRo/100)
        learnings_closed_per = 0 if gaps == 0 else (gapsN/gaps)
        drill_rto_per = 0 if tempp == 0 else (drillsRTO/tempp)

      
        #weightage
        high_Score_ni= 0.08
        medium_Score_ni = 0.05
        low_Score_ni= 0.03

        high_Score_u = 0.01
        medium_Score_u = 0.0
        low_Score_u = 0.0

        #risk score calculation 
        drills_np_rs = 4 if drills_np_per > high_Score_ni else (3 if drills_np_per > medium_Score_ni else (2 if drills_np_per > low_Score_ni else 1))

        u_drills_ns_rs= 4 if u_drills_ns_per > high_Score_ni else (3 if u_drills_ns_per > medium_Score_ni else (2 if u_drills_ns_per > low_Score_ni else 1))
        
        a_dr_i_ns_rs = 4 if a_dr_i_ns_per > high_Score_ni else (3 if a_dr_i_ns_per > medium_Score_ni else (2 if a_dr_i_ns_per > low_Score_ni else 1))
        
        dr_rolled_back_rs = 4 if dr_rolled_back_per > high_Score_u else (3 if dr_rolled_back_per > medium_Score_u else (2 if dr_rolled_back_per > low_Score_u else 1) )
        
        learnings_closed_rs= 0 if learnings_closed_per == 0 else 4 if learnings_closed_per > high_Score_ni else (3 if learnings_closed_per > medium_Score_ni else (2 if learnings_closed_per > low_Score_ni else 1))
    
        drill_rto_rs= 4 if drill_rto_per > high_Score_ni else (3 if drill_rto_per > medium_Score_ni else (2 if drill_rto_per > low_Score_ni else 1))

        #Fetch Previous month score
        last_entry =DrDrill .objects.latest('date')
        
        # last month risk score
        drills_NotPerformed_rs_last = last_entry.drills_NotPerformed_rs
        drills_Unplanned_Unsuccessful_rs_last = last_entry.drills_Unplanned_Unsuccessful_rs
        drills_Unsuccessful_rs_last = last_entry.drills_Unsuccessful_rs
        drills_Rollback_rs_last = last_entry.drills_Rollback_rs
        learnings_Not_Address_rs_last = last_entry.learnings_Not_Address_rs
        drills_Breached_rs_last= last_entry.drills_Breached_rs

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical' ,0:'low'}

        drills_NotPerformed_rs_last_s = severity_mapping.get(drills_NotPerformed_rs_last, 'unknown')
        drills_Unplanned_Unsuccessful_rs_last_s=severity_mapping.get(drills_Unplanned_Unsuccessful_rs_last, 'unknown')
        drills_Unsuccessful_rs_last_s = severity_mapping.get(drills_Unsuccessful_rs_last, 'unknown')
        drills_Rollback_rs_last_s=severity_mapping.get(drills_Rollback_rs_last, 'unknown')
        learnings_Not_Address_rs_last_s = severity_mapping.get(learnings_Not_Address_rs_last, 'unknown')
        drills_Breached_rs_last_s=severity_mapping.get(drills_Breached_rs_last, 'unknown')

        drills_np_rs_s = severity_mapping.get(drills_np_rs, 'unknown')
        u_drills_ns_rs_s=severity_mapping.get(u_drills_ns_rs, 'unknown')
        a_dr_i_ns_rs_s = severity_mapping.get(a_dr_i_ns_rs, 'unknown')
        dr_rolled_back_rs_s=severity_mapping.get(dr_rolled_back_rs, 'unknown')
        learnings_closed_rs_s = severity_mapping.get(learnings_closed_rs, 'unknown')
        drill_rto_rs_s=severity_mapping.get(drill_rto_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        drills_NotPerformed_rs_last_c = map_severity_to_color(drills_NotPerformed_rs_last_s)
        drills_Unsuccessful_rs_last_c = map_severity_to_color(drills_Unsuccessful_rs_last_s)
        drills_Unplanned_Unsuccessful_rs_last_c= map_severity_to_color(drills_Unplanned_Unsuccessful_rs_last_s)
        drills_Rollback_rs_last_c = map_severity_to_color(drills_Rollback_rs_last_s)
        learnings_Not_Address_rs_last_c= map_severity_to_color(learnings_Not_Address_rs_last_s)
        drills_Breached_rs_last_c = map_severity_to_color(drills_Breached_rs_last_s)

        drills_np_rs_c = map_severity_to_color(drills_np_rs_s)
        u_drills_ns_rs_c = map_severity_to_color(u_drills_ns_rs_s)
        a_dr_i_ns_rs_c= map_severity_to_color(a_dr_i_ns_rs_s)
        dr_rolled_back_rs_c = map_severity_to_color(dr_rolled_back_rs_s)
        learnings_closed_rs_c= map_severity_to_color(learnings_closed_rs_s)
        drill_rto_rs_c = map_severity_to_color(drill_rto_rs_s)

        risk = [drills_np_rs,
        u_drills_ns_rs,a_dr_i_ns_rs,dr_rolled_back_rs,learnings_closed_rs,drill_rto_rs
     
            ]  
        weightage = [0.150,0.250,0.100,0.150,0.150,0.200] 

        # Calculate the sum product
        risk_score = np.sum(np.array(weightage) * np.array(risk))
        risk_score=round(risk_score,2)

    

        risk_score_severity=get_severity_color(risk_score)

        w_instance=Category.objects.get(name='DR Drill')
        name=w_instance.name
       
        r_instance=DRRiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=1.00
        )

        r_instance.save()
        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'DrDrill',
            'email': email,
            'RISKSCORE':risk_score,
            'risk_score_severity':risk_score_severity,
            

            #RS

            'drills_np_rs': drills_np_rs,
            'u_drills_ns_rs': u_drills_ns_rs,
            'a_dr_i_ns_rs': a_dr_i_ns_rs,
            'dr_rolled_back_rs': dr_rolled_back_rs,
            'learnings_closed_rs': learnings_closed_rs,
            'drill_rto_rs': drill_rto_rs,

            'drills_NotPerformed_rs_last': drills_NotPerformed_rs_last,
            'drills_Unplanned_Unsuccessful_rs_last': drills_Unplanned_Unsuccessful_rs_last,
            'drills_Unsuccessful_rs_last': drills_Unsuccessful_rs_last,
            'drills_Rollback_rs_last': drills_Rollback_rs_last,
            'learnings_Not_Address_rs_last': learnings_Not_Address_rs_last,
            'drills_Breached_rs_last': drills_Breached_rs_last,

            #Severity
            
            'drills_NotPerformed_rs_last_s':drills_NotPerformed_rs_last_s,
            'drills_Unplanned_Unsuccessful_rs_last_s':drills_Unplanned_Unsuccessful_rs_last_s,
            'drills_Unsuccessful_rs_last_s': drills_Unsuccessful_rs_last_s,
            'drills_Rollback_rs_last_s': drills_Rollback_rs_last_s,
            'learnings_Not_Address_rs_last_s': learnings_Not_Address_rs_last_s,
            'drills_Breached_rs_last_s': drills_Breached_rs_last_s,
            
            'drills_np_rs_s':drills_np_rs_s,
            'u_drills_ns_rs_s':u_drills_ns_rs_s,
            'a_dr_i_ns_rs_s': a_dr_i_ns_rs_s,
            'dr_rolled_back_rs_s': dr_rolled_back_rs_s,
            'learnings_closed_rs_s': learnings_closed_rs_s,
            'drill_rto_rs_s': drill_rto_rs_s,


            # color
            'drills_NotPerformed_rs_last_c': drills_NotPerformed_rs_last_c,
            'drills_Unsuccessful_rs_last_c': drills_Unsuccessful_rs_last_c,
            'drills_Unplanned_Unsuccessful_rs_last_c': drills_Unplanned_Unsuccessful_rs_last_c,
            'drills_Rollback_rs_last_c': drills_Rollback_rs_last_c,
            'learnings_Not_Address_rs_last_c': learnings_Not_Address_rs_last_c,
            'drills_Breached_rs_last_c': drills_Breached_rs_last_c,

            'drills_np_rs_c': drills_np_rs_c,
            'u_drills_ns_rs_c': u_drills_ns_rs_c,
            'a_dr_i_ns_rs_c': a_dr_i_ns_rs_c,
            'dr_rolled_back_rs_c': dr_rolled_back_rs_c,
            'learnings_closed_rs_c': learnings_closed_rs_c,
            'drill_rto_rs_c': drill_rto_rs_c,



        }


        dlp_instances=DrDrill(

            drills_Total = drills,
            drills_Unsuccessful =drillsS,
            drills_NotPerformed = drillsNP,
            drills_Unplanned = drillsU,
            drills_Unplanned_Unsuccessful = drillsUNS,
            drills_Actual_Dr_Invocation = drillsA,
            drill_Actual_Dr_Invocation_Not_Successful = drillsNS,
            drills_Rollback = drillsRo,
            gaps_identified = gaps,
            gaps_Not_Addressed= gapsN,
            drills_Breached_RTO = drillsRTO,
            
            drills_NotPerformed_per = drills_np_per,
            drills_Unplanned_Unsuccessful_per = u_drills_ns_per,
            drills_Unsuccessful_per= a_dr_i_ns_per,
            drills_Rollback_per = dr_rolled_back_per,
            learnings_Not_Address_per= learnings_closed_per,
            drills_Breached_per = drill_rto_per,

            drills_NotPerformed_rs =  drills_np_rs,
            drills_Unplanned_Unsuccessful_rs =  u_drills_ns_rs,
            drills_Unsuccessful_rs= a_dr_i_ns_rs,
            drills_Rollback_rs =  dr_rolled_back_rs,
            learnings_Not_Address_rs=  learnings_closed_rs,
            drills_Breached_rs =  drill_rto_rs,

         
            Evidence=save_path,
          
        )

        dlp_instances.save()
        return render(request ,'kriaApp/drDrill.html',context)
    elif 'validate' in request.POST:
        flag = request.POST.get('flag')
        if flag == '1':
            drills_NotPerformed_Justification=request.POST.get('drills_NotPerformed_Justification')

            drills_Unplanned_Unsuccessful_Justification=request.POST.get('drills_Unplanned_Unsuccessful_Justification')

            drills_Unsuccessful_Justification=request.POST.get('drills_Unsuccessful_Justification')

            drills_Rollback_Justification=request.POST.get('drills_Rollback_Justification')

            learnings_Not_Address_Justification=request.POST.get('learnings_Not_Address_Justification')

            drills_Breached_Justification=request.POST.get('drills_Breached_Justification')

       
            # Get the latest instance of Appsec from the database
            instance = DrDrill.objects.latest('date')
          
            # Update the latest instance with the justifications
            instance.drills_NotPerformed_Justification=drills_NotPerformed_Justification

            instance.drills_Unplanned_Unsuccessful_Justification=drills_Unplanned_Unsuccessful_Justification

            instance.drills_Unsuccessful_Justification=drills_Unsuccessful_Justification

            instance.drills_Rollback_Justification=drills_Rollback_Justification

            instance.learnings_Not_Address_Justification=learnings_Not_Address_Justification

            instance.drills_Breached_Justification=drills_Breached_Justification

           
            try:
                latest_appsec_instance.save()
            except Exception as e:
                print("Error while saving to the database:", str(e))
        
            
        status='success'
        context={
                'status':status,
                'email': email
            }
        Team.objects.filter(id='5').update(status=1)
        check_status_if_all_submitted()

       


        #******************* Session Object Start *************************    


        drills=request.session.get('drills') 
        drillsS=request.session.get('drillsS') 
        drillsNP=request.session.get('drillsNP') 

        drillsU=request.session.get('drillsU') 
        drillsUNS=request.session.get('drillsUNS')
        drillsA=request.session.get('drillsA') 

        drillsNS=request.session.get('drillsNS') 
        drillsRo=request.session.get('drillsRo') 

        gaps=request.session.get('gaps') 
        gapsN=request.session.get('gapsN') 
        drillsRTO=request.session.get('drillsRTO') 

        session_data_dict = {'DR DRILL':{"Drills Planned" : drills,"Planned DR drill not successfu" : drillsS,"Drills not performed (Having Exception)" : drillsNP,"Unplanned Drills (Surprise/Test/Roll back /Activity Based)" : drillsU,"Unplanned Drills not successful" : drillsUNS,"Actual DR invocation (Emergency)" : drillsA,"Actual DR invocation not successful" : drillsNS,"DR Rolled back in < 24 hours (Other than CTS)" : drillsRo,"Gaps identified(Repetitive RTO breach -- in Q1 FY2021-22 (Count based on applications - not instances)" : gaps,"Gaps not addressed -- in Q2 FY 2021-22 (Count based on applications - not instances) " : gapsN,"DR drill breached RTO" : drillsRTO}
        }

        data=Team.objects.get(id='5')
        send_email(data.team,data.owner,session_data_dict) 

        #******************* Session Object Start ************************* 

        return render(request ,'kriaApp/drDrill.html',context)
    return render(request ,'kriaApp/drDrill.html',context)


def soc(request):
    email = request.session.get('name') 
    context={}


    # temp=Team.objects.get(id='6')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

    context={
            'email':email
    }
    global tag

    if 'eValidate' in request.POST:
        score_fields = ['total', 'critical', 'medium','low','critical_open','medium_open']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        total=scores['total']
        critical=scores['critical']
        medium=scores['medium']
        low=scores['low']
        critical_open=scores['critical_open']
        medium_open=scores['medium_open']

        #******************* Session Object Start *************************    
        request.session['total']=total
        request.session['critical']=critical
        request.session['medium']=medium
        request.session['low']=low
        request.session['critical_open']=critical_open
        request.session['medium_open']=medium_open

        #******************* Session Object Start *************************  
              



        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)
                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation

        if total == 0:
            critical_per = 0
            medium_per=0
            low_per=0
            critical_open_per=0
            medium_open_per=0
        else:
            critical_per = round(critical/total,3)
            medium_per=round(medium/total,3)
            low_per=round(low/total,3)
            critical_open_per=round(critical_open/total,3)
            medium_open_per=round(medium_open/total,3)

        #weightage
        high_Score_c= 0.30
        medium_Score_c = 0.20
        low_Score_c= 0.15

        high_Score_co = 0.05
        medium_Score_co = 0.03
        low_Score_co = 0.0


        #risk score calculation 
        critical_rs = 4 if critical_per > high_Score_c else (3 if critical_per > medium_Score_c else (2 if critical_per > low_Score_c else 1))

        critical_open_rs = 4 if critical_open_per > high_Score_co else (3 if critical_open_per > medium_Score_co else (2 if critical_open_per > low_Score_co else 1))
    
        ###FINAL RISK CALCULATION
        risk = [critical_rs, critical_open_rs]  
        weightage = [0.4, 0.6] 
        risk_score = np.sum(np.array(weightage) * np.array(risk))

        w_instance=Category.objects.get(name='SOC Incidents - External')
        name=w_instance.name
       
        r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.2
        )

        r_instance.save()
        
        ###FINAL RISK CALCULATION END

        #Fetch Previous month score
        last_entry = SOC_External.objects.latest('date')
        
        # last month risk score
        critical_rs_last = last_entry.critical_and_high_rs
        critical_open_rs_last = last_entry.critical_and_high_open_rs

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        critical_rs_last_s = severity_mapping.get(critical_rs_last, 'unknown')
        critical_open_rs_last_s=severity_mapping.get(critical_open_rs_last, 'unknown')
        critical_rs_s = severity_mapping.get(critical_rs, 'unknown')
        critical_open_rs_s=severity_mapping.get(critical_open_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        critical_rs_last_c = map_severity_to_color(critical_rs_last_s)
        critical_open_rs_last_c = map_severity_to_color(critical_open_rs_last_s)
        critical_rs_c= map_severity_to_color(critical_rs_s)
        critical_open_rs_c = map_severity_to_color(critical_open_rs_s)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'SOC_External',
            'email': email,
            'critical_open_rs_last':critical_open_rs_last,
            'critical_rs_last':critical_rs_last,
            'critical_open_rs':critical_open_rs,
            'critical_rs':critical_rs,
            'critical_open_rs_last_s':critical_open_rs_last_s,
            'critical_rs_last_s':critical_rs_last_s,
            'critical_open_rs_s':critical_open_rs_s,
            'critical_rs_s':critical_rs_s,
            'critical_open_rs_last_c':critical_open_rs_last_c,
            'critical_rs_last_c':critical_rs_last_c,
            'critical_open_rs_c':critical_open_rs_c,
            'critical_rs_c':critical_rs_c,
        }

       
        dlp_instances=SOC_External(
            external=total,
            critical_and_high=critical,
            medium=medium,
            low=low,
            critical_and_high_open=critical_open,
            medium_open=medium_open,
            critical_and_high_per=critical_per,
            critical_and_high_open_per=critical_open_per,
            critical_and_high_rs=critical_rs,
            critical_and_high_open_rs=critical_open_rs,
            Evidence=save_path

        )

        dlp_instances.save()
        return render(request ,'kriaApp/soc.html',context)
    elif 'Vsubmit' in request.POST:
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', team)
        for i in tag1:
            # print("***************************************************")
            # print(i)
            if flag == '1':
                critical_justification=request.POST.get('critical_justification')
                critical_open_justification=request.POST.get('critical_open_justification')
                latest_instance = ModelClass.objects.latest('date')
                latest_instance.critical_justification = critical_justification
                latest_instance.critical_open_justification = critical_open_justification
                latest_instance.save()

            tag1.pop(0)
            context = {
                'email': email,
                'status':i
                }

            return render(request ,'kriaApp/soc.html',context)
    elif 'iValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'iValidate' in request.POST:
               score_fields = ['total', 'critical','critical_open']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        total=scores['total']
        critical=scores['critical']
        critical_open=scores['critical_open']

        #******************* Session Object Start *************************    
        request.session['soci_total']=total
        request.session['soci_critical']=critical
        request.session['soci_critical_open']=critical_open

        #******************* Session Object Start *************************  
      
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']
            static_dir = os.path.join(os.path.dirname(__file__), 'static')
            save_dir = os.path.join(static_dir, 'media')
            uploaded_image = uploaded_file
            name=uploaded_image.name
            # print(name)
            os.makedirs(save_dir, exist_ok=True)  

            save_path1 = os.path.join(save_dir, name)
            save_path = save_path1.split('/')
            save_path = '/'.join(save_path[6:])
            base_url = 'https://kritracker.npci.org.in/'
            save_path = base_url  + save_path

            # print(save_path)
            # Save the uploaded image to the specified path
            with open(save_path1, 'wb') as f:
                for chunk in uploaded_image.chunks():
                    f.write(chunk)

        #Percentage Calculation
        critical_per =round(critical/total,3)
        critical_open_per=round(critical_open/total,3)

        #weightage
        high_Score_c= 0.30
        medium_Score_c = 0.20
        low_Score_c= 0.10

        high_Score_co = 0.30
        medium_Score_co = 0.20
        low_Score_co = 0.15


        #risk score calculation 
        critical_rs = 4 if critical_per > high_Score_c else (3 if critical_per > medium_Score_c else (2 if critical_per > low_Score_c else 1))

        critical_open_rs = 4 if critical_open_per > high_Score_co else (3 if critical_open_per > medium_Score_co else (2 if critical_open_per > low_Score_co else 1))
    

         ###FINAL RISK CALCULATION
        risk = [critical_rs, critical_open_rs]  
        weightage = [0.4, 0.6] 
        risk_score = np.sum(np.array(weightage) * np.array(risk))

        w_instance=Category.objects.get(name='SOC Incidents - Internal')
        name=w_instance.name
       
        r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.2

        )

        r_instance.save()
        
        ###FINAL RISK CALCULATION END

        #Fetch Previous month score
        last_entry = SOC_Internal.objects.latest('date')
        
        # last month risk score
        critical_rs_last = last_entry.critical_open_risk_score
        critical_open_rs_last = last_entry.critical_identifies_risk_score

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        critical_rs_last_s = severity_mapping.get(critical_rs_last, 'unknown')
        critical_open_rs_last_s=severity_mapping.get(critical_open_rs_last, 'unknown')
        critical_rs_s = severity_mapping.get(critical_rs, 'unknown')
        critical_open_rs_s=severity_mapping.get(critical_open_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        critical_rs_last_c = map_severity_to_color(critical_rs_last_s)
        critical_open_rs_last_c = map_severity_to_color(critical_open_rs_last_s)
        critical_rs_c= map_severity_to_color(critical_rs_s)
        critical_open_rs_c = map_severity_to_color(critical_open_rs_s)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'SOC_Internal',
            'email': email,
            'critical_open_rs_last':critical_open_rs_last,
            'critical_rs_last':critical_rs_last,
            'critical_open_rs':critical_open_rs,
            'critical_rs':critical_rs,
            'critical_open_rs_last_s':critical_open_rs_last_s,
            'critical_rs_last_s':critical_rs_last_s,
            'critical_open_rs_s':critical_open_rs_s,
            'critical_rs_s':critical_rs_s,
            'critical_open_rs_last_c':critical_open_rs_last_c,
            'critical_rs_last_c':critical_rs_last_c,
            'critical_open_rs_c':critical_open_rs_c,
            'critical_rs_c':critical_rs_c,
        }

       
        dlp_instances=SOC_Internal(
            internal_total=total,
            crtitical_open=critical,
            critical_identifies=critical_open,
            crtitical_open_per=critical_per,
            critical_identifies_per=critical_open_per,
            critical_open_risk_score=critical_rs,
            critical_identifies_risk_score=critical_open_rs,
            Evidence=save_path

        )

        dlp_instances.save()
        return render(request ,'kriaApp/soc.html',context)
    
    elif 'osValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'osValidate' in request.POST:
            score_fields = ['windows', 'linux']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            windows=scores['windows']
            linux=scores['linux']

            #******************* Session Object Start *************************    
            request.session['windows']=windows
            request.session['linux']=linux
           
            #******************* Session Object Start *************************  
          


            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                print(name)
                os.makedirs(save_dir, exist_ok=True)  

                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)



           

            context= {
                'status':'sucess',
                'email': email,
            }

            dlp_instances=SOCOS(
                windows=windows,
                linux=linux,
                os_Evidence=save_path
            )

            dlp_instances.save()
            Team.objects.filter(id='6').update(status=1)
            check_status_if_all_submitted()

            data=Team.objects.get(id='6')


            #******************* Session Object Start *************************    

            total = request.session.get('total')
            critical =request.session.get('critical')
            medium = request.session.get('medium')
            low = request.session.get('low')
            critical_open = request.session.get('critical_open')
            medium_open = request.session.get('medium_open')

            soci_total = request.session.get('soci_total')
            soci_critical = request.session.get('soci_critical')
            soci_critical_open = request.session.get('soci_critical_open')

            windows = request.session.get('windows')
            linux = request.session.get('linux')


            session_data_dict = {'SOC - External':{"Total External Incidents" : total,"Total critical & high incidents" : critical,"Total medium incidents" : medium,"Total low incidents" : low,"Total critical & high incidents - open" : critical_open,"Total medium incidents - open" : medium_open}, 'SOC - Internal':{"Total Internal Incidents" : soci_total,"Total critical & high incidents - open" : soci_critical,"Total critical & high incidents - identified" : soci_critical_open},'SOC - Operating System':{"Total Windows Server" : windows,"Total Linux+ Other Servers" : linux}}

            #******************* Session Object Start *************************  

            send_email(data.team,data.owner,session_data_dict) 
           

            return render(request ,'kriaApp/soc.html',context)
       
    
    return render(request ,'kriaApp/soc.html',context)


def patch(request):
    email = request.session.get('name') 
    context = {'email': email}

    # temp=Team.objects.get(id='7')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

    
    if 'patch' in request.POST:
        score_fields = ['windows_cloud', 'non_windows_cloud', 'db_cloud' ,'windows_physical','nw_physical' ,'db_physical'  ,'w_critical','w_medium','w_n_mius_2_os','nw_critical','nw_medium','nw_n_os','db_critical','db_medium','db_n_minus_2_os']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        windows_cloud=scores['windows_cloud']
        non_windows_cloud=scores['non_windows_cloud']
        db_cloud=scores['db_cloud']

        windows_physical=scores['windows_physical']
        nw_physical=scores['nw_physical']
        db_physical=scores['db_physical']

        w_critical=scores['w_critical']
        w_medium=scores['w_medium']
        w_n_mius_2_os=scores['w_n_mius_2_os']

        nw_critical=scores['nw_critical']
        nw_medium=scores['nw_medium']
        nw_n_os=scores['nw_n_os']

        db_critical=scores['db_critical']
        db_medium=scores['db_medium']
        db_n_minus_2_os=scores['db_n_minus_2_os']


        request.session['windows_cloud']= windows_cloud
        request.session['non_windows_cloud']=  non_windows_cloud
        request.session['db_cloud']= db_cloud

        request.session['windows_physical']= windows_physical
        request.session['nw_physical']=  nw_physical
        request.session['db_physical']= db_physical

        request.session['w_critical']= w_critical
        request.session['w_medium']= w_medium
        request.session['w_n_mius_2_os']= w_n_mius_2_os

        request.session['nw_critical']= nw_critical
        request.session['nw_medium']= nw_medium
        request.session['nw_n_os']= nw_n_os

        request.session['db_critical']= db_critical
        request.session['db_medium']=  db_medium
        request.session['db_n_minus_2_os']= db_n_minus_2_os

    
      

        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        


        total_w = windows_cloud + windows_physical
        total_nw = non_windows_cloud + nw_physical
        total_db = db_cloud + db_physical 
        #Percentage Calculation

        w_critical_per = round(w_critical/total_w,3)
        w_medium_per = round(w_medium/total_w,3)
        w_n_mius_2_os_per = round(w_n_mius_2_os/total_w,3)

        nw_critical_per = round(nw_critical/total_nw,3)
        nw_medium_per = round(nw_medium/total_nw,3)
        nw_n_os_per = round(nw_n_os/total_nw,3)

        db_critical_per = round(db_critical/total_db,3)
        db_medium_per = round(db_medium/total_db,3)
        db_n_minus_2_os_per = round(db_n_minus_2_os/total_db,3)

        #weightage
        high_Score_ni= 0.08
        medium_Score_ni = 0.05
        low_Score_ni= 0.03

        #risk score calculation 
        w_critical_rs = 4 if w_critical_per > high_Score_ni else (3 if w_critical_per > medium_Score_ni else (2 if w_critical_per > low_Score_ni else 1))

        w_medium_rs = 4 if w_medium_per > high_Score_ni else (3 if w_medium_per > medium_Score_ni else (2 if w_medium_per > low_Score_ni else 1))

        w_n_mius_2_os_rs = 4 if w_n_mius_2_os_per > high_Score_ni else (3 if w_n_mius_2_os_per > medium_Score_ni else (2 if w_n_mius_2_os_per > low_Score_ni else 1))

        nw_critical_rs = 4 if nw_critical_per > high_Score_ni else (3 if nw_critical_per > medium_Score_ni else (2 if nw_critical_per > low_Score_ni else 1))

        nw_medium_rs = 4 if nw_medium_per > high_Score_ni else (3 if nw_medium_per > medium_Score_ni else (2 if nw_medium_per > low_Score_ni else 1))

        nw_n_os_rs = 4 if nw_n_os_per > high_Score_ni else (3 if nw_n_os_per > medium_Score_ni else (2 if nw_n_os_per > low_Score_ni else 1))

        db_critical_rs = 4 if db_critical_per > high_Score_ni else (3 if db_critical_per > medium_Score_ni else (2 if db_critical_per > low_Score_ni else 1))

        db_medium_rs = 4 if db_medium_per > high_Score_ni else (3 if db_medium_per > medium_Score_ni else (2 if db_medium_per > low_Score_ni else 1))

        db_n_minus_2_os_rs = 4 if db_n_minus_2_os_per > high_Score_ni else (3 if db_n_minus_2_os_per > medium_Score_ni else (2 if db_n_minus_2_os_per > low_Score_ni else 1))

      
        #Fetch Previous month score
        last_entry = Patch.objects.latest('date')
        
        # last month risk score
        w_critical_rs_last = last_entry.w_critical_rs
        w_medium_rs_last = last_entry.w_medium_rs
        w_n_mius_2_os_rs_last = last_entry.w_n_mius_2_os_rs

        nw_critical_rs_last = last_entry.nw_critical_rs
        nw_medium_rs_last = last_entry.nw_medium_rs
        nw_n_os_rs_last = last_entry.nw_n_os_rs

        db_critical_rs_last= last_entry.db_critical_rs
        db_medium_rs_last= last_entry.db_medium_rs
        db_n_minus_2_os_rs_last = last_entry.db_n_minus_2_os_rs

        # severity calculation
        #LAst Month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
       
        w_critical_s_last = severity_mapping.get(w_critical_rs_last, 'unknown')
        w_medium_s_last=severity_mapping.get(w_medium_rs_last, 'unknown')
        w_n_mius_2_os_s_last = severity_mapping.get(w_n_mius_2_os_rs_last, 'unknown')
        
        nw_critical_s_last = severity_mapping.get(nw_critical_rs_last, 'unknown')
        nw_medium_s_last=severity_mapping.get(nw_medium_rs_last, 'unknown')
        nw_n_os_s_last = severity_mapping.get(nw_n_os_rs_last, 'unknown')
        
        db_critical_s_last = severity_mapping.get(db_critical_rs_last, 'unknown')
        db_medium_s_last=severity_mapping.get(db_medium_rs_last, 'unknown')
        db_n_minus_2_os_s_last = severity_mapping.get(db_n_minus_2_os_rs_last, 'unknown')

         #Current Month
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
    
        w_critical_s = severity_mapping.get(w_critical_rs, 'unknown')
        w_medium_s=severity_mapping.get(w_medium_rs, 'unknown')
        w_n_mius_2_os_s = severity_mapping.get(w_n_mius_2_os_rs, 'unknown')
        
        nw_critical_s = severity_mapping.get(nw_critical_rs, 'unknown')
        nw_medium_s=severity_mapping.get(nw_medium_rs, 'unknown')
        nw_n_os_s = severity_mapping.get(nw_n_os_rs, 'unknown')
        
        db_critical_s = severity_mapping.get(db_critical_rs, 'unknown')
        db_medium_s=severity_mapping.get(db_medium_rs, 'unknown')
        db_n_minus_2_os_s= severity_mapping.get(db_n_minus_2_os_rs, 'unknown')
   
                

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        #Last Month
      
        w_critical_c_last = map_severity_to_color(w_critical_s_last)
        w_medium_c_last = map_severity_to_color(w_medium_s_last)
        w_n_mius_2_os_c_last= map_severity_to_color(w_n_mius_2_os_s_last)

        nw_critical_c_last = map_severity_to_color(nw_critical_s_last)
        nw_medium_c_last = map_severity_to_color(nw_medium_s_last)
        nw_n_os_c_last= map_severity_to_color(nw_n_os_s_last)

        db_critical_c_last = map_severity_to_color(db_critical_s_last)
        db_medium_c_last = map_severity_to_color(db_medium_s_last)
        db_n_minus_2_os_c_last= map_severity_to_color(db_n_minus_2_os_s_last)

        #Current Month
     
        w_critical_c = map_severity_to_color(w_critical_s)
        w_medium_c = map_severity_to_color(w_medium_s)
        w_n_mius_2_os_c= map_severity_to_color(w_n_mius_2_os_s)

        nw_critical_c = map_severity_to_color(nw_critical_s)
        nw_medium_c = map_severity_to_color(nw_medium_s)
        nw_n_os_c= map_severity_to_color(nw_n_os_s)

        db_critical_c = map_severity_to_color(db_critical_s)
        db_medium_c = map_severity_to_color(db_medium_s)
        db_n_minus_2_os_c= map_severity_to_color(db_n_minus_2_os_s)


        network=Network.objects.latest('date')

        total_n=network.Total 

        nt_critical_and_high_rs=network.critical_and_high_rs
        nt_medium_rs=network.medium_rs
        nt_n_mius_2_os_rs=network.n_mius_2_os_rs

        
        total=total_db+total_w+total_nw+total_n

        risk = [
            w_critical_rs, 
            w_medium_rs,
            w_n_mius_2_os_rs,

            nw_critical_rs, 
            nw_medium_rs,
            nw_n_os_rs,

            db_critical_rs, 
            db_medium_rs,
            db_n_minus_2_os_rs,

            nt_critical_and_high_rs,
            nt_medium_rs,
            nt_n_mius_2_os_rs,

            ]  

    
        weightage = [0.100,0.050,0.100,0.100,0.050,0.100,0.100,0.050,0.100,0.100,0.050,0.100] 

        

        # Calculate the sum product
        risk_score = np.sum(np.array(weightage) * np.array(risk))
        risk_score=round(risk_score,2)

    

        risk_score_severity=get_severity_color(risk_score)

        w_instance=Category.objects.get(name='Patch')
        name=w_instance.name
       
        r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.1
        )

        r_instance.save()

        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'Patch',
            'email': email,
            'RISKSCORE':risk_score,
            'risk_score_severity':risk_score_severity,
            
            'w_critical_rs_last':w_critical_rs_last,
            'w_medium_rs_last':w_medium_rs_last,
            'w_n_mius_2_os_rs_last':w_n_mius_2_os_rs_last,
            'nw_critical_rs_last':nw_critical_rs_last,
            'nw_medium_rs_last':nw_medium_rs_last,
            'nw_n_os_rs_last':nw_n_os_rs_last,
            'db_critical_rs_last':db_critical_rs_last,
            'db_medium_rs_last':db_medium_rs_last,
            'db_n_minus_2_os_rs_last':db_n_minus_2_os_rs_last,


            'w_critical_rs':w_critical_rs,
            'w_medium_rs':w_medium_rs,
            'w_n_mius_2_os_rs':w_n_mius_2_os_rs,
            'nw_critical_rs':nw_critical_rs,
            'nw_medium_rs':nw_medium_rs,
            'nw_n_os_rs':nw_n_os_rs,
            'db_critical_rs':db_critical_rs,
            'db_medium_rs':db_medium_rs,
            'db_n_minus_2_os_rs':db_n_minus_2_os_rs,

            'w_critical_s_last':w_critical_s_last,
            'w_medium_s_last':w_medium_s_last,
            'w_n_mius_2_os_s_last':w_n_mius_2_os_s_last,
            'nw_critical_s_last':nw_critical_s_last,
            'nw_medium_s_last':nw_medium_s_last,
            'nw_n_os_s_last':nw_n_os_s_last,
            'db_critical_s_last':db_critical_s_last,
            'db_medium_s_last':db_medium_s_last,
            'db_n_minus_2_os_s_last':db_n_minus_2_os_s_last,
            
            'w_critical_s':w_critical_s,
            'w_medium_s':w_medium_s,
            'w_n_mius_2_os_s':w_n_mius_2_os_s,
            'nw_critical_s':nw_critical_s,
            'nw_medium_s':nw_medium_s,
            'nw_n_os_s':nw_n_os_s,
            'db_critical_s':db_critical_s,
            'db_medium_s':db_medium_s,
            'db_n_minus_2_os_s':db_n_minus_2_os_s,

            'w_critical_c_last':w_critical_c_last,
            'w_medium_c_last':w_medium_c_last,
            'w_n_mius_2_os_c_last':w_n_mius_2_os_c_last,
            'nw_critical_c_last':nw_critical_c_last,
            'nw_medium_c_last':nw_medium_c_last,
            'nw_n_os_c_last':nw_n_os_c_last,
            'db_critical_c_last':db_critical_c_last,
            'db_medium_c_last':db_medium_c_last,
            'db_n_minus_2_os_c_last':db_n_minus_2_os_c_last,

            'w_critical_c':w_critical_c,
            'w_medium_c':w_medium_c,
            'w_n_mius_2_os_c':w_n_mius_2_os_c,
            'nw_critical_c':nw_critical_c,
            'nw_medium_c':nw_medium_c,
            'nw_n_os_c':nw_n_os_c,
            'db_critical_c':db_critical_c,
            'db_medium_c':db_medium_c,
            'db_n_minus_2_os_c':db_n_minus_2_os_c,
    
        }

        dlp_instances=Patch(
            total=total,

            windows_cloud=windows_cloud,
            non_windows_cloud=non_windows_cloud,
            db_cloud=db_cloud,
            windows_physical=windows_physical,
            nw_physical=nw_physical,
            db_physical=db_physical,
            
            w_critical=w_critical,
            w_medium=w_medium,
            w_n_mius_2_os=w_n_mius_2_os,

            nw_critical=nw_critical,
            nw_medium=nw_medium,
            nw_n_os=nw_n_os,

            db_critical=db_critical,
            db_medium=db_medium,
            db_n_minus_2_os=db_n_minus_2_os,

            #pere

            w_critical_per=w_critical_per,
            w_medium_per=w_medium_per,
            w_n_mius_2_os_per=w_n_mius_2_os_per,

            nw_critical_per=nw_critical_per,
            nw_medium_per=nw_medium_per,
            nw_n_os_per=nw_n_os_per,

            db_critical_per=db_critical_per,
            db_medium_per=db_medium_per,
            db_n_minus_2_os_per=db_n_minus_2_os_per,

            #Risk Score

            w_critical_rs=w_critical_rs,
            w_medium_rs=w_medium_rs,
            w_n_mius_2_os_rs=w_n_mius_2_os_rs,
            nw_critical_rs=nw_critical_rs,
            nw_medium_rs=nw_medium_rs,
            nw_n_os_rs=nw_n_os_rs,
            db_critical_rs=db_critical_rs,
            db_medium_rs=db_medium_rs,
            db_n_minus_2_os_rs=db_n_minus_2_os_rs,

            Evidence=save_path
        )
        
        dlp_instances.save()
        return render(request ,'kriaApp/patch.html',context)

    elif 'Vsubmit' in request.POST:
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', "Patch")
       
        if flag == '1':
            w_critical_justification=request.POST.get('w_critical_justification')
            w_medium_justification=request.POST.get('w_medium_justification')
            w_n_mius_2_os_justification=request.POST.get('w_n_mius_2_os_justification')

            nw_critical_justification=request.POST.get('nw_critical_justification')
            nw_medium_justification=request.POST.get('nw_medium_justification')
            nw_n_os_justification=request.POST.get('nw_n_os_justification')

            db_critical_justification=request.POST.get('db_critical_justification')
            db_medium_justification=request.POST.get('db_medium_justification')
            db_n_minus_2_os_justification=request.POST.get('db_n_minus_2_os_justification')

            latest_instance = ModelClass.objects.latest('date')


            latest_instance.w_critical_justification = w_critical_justification
            latest_instance.w_medium_justification = w_medium_justification
            latest_instance.w_n_mius_2_os_justification = w_n_mius_2_os_justification

            latest_instance.nw_critical_justification = nw_critical_justification
            latest_instance.nw_medium_justification = nw_medium_justification
            latest_instance.nw_n_os_justification = nw_n_os_justification

            latest_instance.db_critical_justification = db_critical_justification
            latest_instance.db_medium_justification = db_medium_justification
            latest_instance.db_n_minus_2_os_justification = db_n_minus_2_os_justification


            latest_instance.save()
          
            context = {
                'email': email,
                'status':"success"
                }
            
            Team.objects.filter(id='7').update(status=1)
            check_status_if_all_submitted()

            data=Team.objects.get(id='7')
            

            #******************* Session Object Start *************************    

            windows_cloud = request.session.get('windows_cloud') 
            non_windows_cloud = request.session.get('non_windows_cloud') 
            db_cloud = request.session.get('db_cloud') 

            windows_physical = request.session.get('windows_physical') 
            nw_physical = request.session.get('nw_physical') 
            db_physical = request.session.get('db_physical') 

            w_critical = request.session.get('w_critical') 
            w_medium = request.session.get('w_medium') 
            w_n_mius_2_os = request.session.get('w_n_mius_2_os') 

            nw_critical = request.session.get('nw_critical') 
            nw_medium = request.session.get('nw_medium') 
            nw_n_os = request.session.get('nw_n_os') 

            db_critical = request.session.get('db_critical') 
            db_medium = request.session.get('db_medium') 
            db_n_minus_2_os = request.session.get('db_n_minus_2_os') 


            session_data_dict = {'Patch Status':{"Total Windows Cloud Server" : windows_cloud,"Total Non-Windows Cloud Server" : non_windows_cloud,"Total DB Cloud Server" : db_cloud,"Total Windows Physical Server" : windows_physical,"Total Non-Windows Physical servers" : nw_physical,"Total DB Physical servers" : db_physical,"Windows servers not patched with Critical &    High (>30 days)" : w_critical,"Windows servers not patched with Medium (>60 days)" : w_medium,">Windows servers running N-2 OS version(n=Current Version)" : w_n_mius_2_os,"Non-Windows servers not patched with Critical & High (>30 days)" : nw_critical,"Non-Windows servers not patched with Medium (>60 days)" : nw_medium,"Non-Windows servers running N-2 OS version (N=current version)" : nw_n_os,"DB servers not patched with Critical & High (>30 days)" : db_critical,"DB servers not patched with Medium (>60 days)" : db_medium,"DB servers running N-2 OS version (N=current version)" : db_n_minus_2_os}
            }

            #******************* Session Object Start *************************  

            send_email(data.team,data.owner,session_data_dict) 

            return render(request ,'kriaApp/patch.html',context)
    return render(request ,'kriaApp/patch.html',context)

    return render(request ,'kriaApp/patch.html',context)


def assetManage(request):
    email = request.session.get('name') 
    context = {'email': email}


    # temp=Team.objects.get(id='8')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


    if 'assetManage' in request.POST:
        score_fields = ['dlpI', 'dlpNI', 'dlpU']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        dlpI=scores['dlpI']
        dlpNI=scores['dlpNI']
        dlpU=scores['dlpU']

        #******************* Session Object Start *************************    
        request.session['asset_dlpI']=dlpI
        request.session['asset_dlpNI']=dlpNI
        request.session['asset_dlpU']=dlpU

        #******************* Session Object Start *************************  



        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation
        dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
        dlpU_per = round(dlpU/dlpI,3)

        #weightage
        high_Score_ni= 0.15
        medium_Score_ni = 0.10
        low_Score_ni= 0.05

        high_Score_u = 0.10
        medium_Score_u = 0.08
        low_Score_u = 0.05


        #risk score calculation 
        dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

        dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))




        #Fetch Previous month score
        last_entry = AssetManagment.objects.latest('date')
        
        # last month risk score
        dlpNI_rs_last = last_entry.uninstalled_risk_score
        dlpU_rs_last = last_entry.unhealthy_risk_score

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
        dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
        dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
        dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
        color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
        color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
        color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'AssetManagment',
            'email': email,
            'uninstalled':dlpNI_rs,
            'unhealthy':dlpU_rs,
            'uninstalled_last':dlpNI_rs_last,
            'unhealthy_last':dlpU_rs_last,
            'severity_last_NI':dlpNI_rs_severity_last,
            'severity_last_U':dlpU_rs_severity_last,
            'severity_current_NI':dlpNI_rs_severity,
            'severity_current_U':dlpU_rs_severity,
            'color_last_NI':color_dlpNI_rs_last,
            'color_current_NI':color_dlpNI_rs,
            'color_last_U':color_dlpU_rs__last,
            'color_current_U':color_dlpU_rs,
        }


        dlp_instances=AssetManagment(
            installed = dlpI,
            uninstalled = dlpNI,
            unhealthy = dlpU,
            uninstalled_per = dlpNI_per,
            unhealthy_per =dlpU_per,
            uninstalled_risk_score = dlpNI_rs,
            unhealthy_risk_score = dlpU_rs,
            Evidence=save_path
        )

        dlp_instances.save()
        return render(request ,'kriaApp/assetManage.html',context)
    elif 'Vsubmit' in request.POST:
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', "AssetManagment")
       
        if flag == '1':
            uninstalled_justification=request.POST.get('uninstalled_justification')
            unhealthy_justification=request.POST.get('unhealthy_justification')
            latest_instance = ModelClass.objects.latest('date')
            latest_instance.uninstalled_justification = uninstalled_justification
            latest_instance.unhealthy_justification = unhealthy_justification
            latest_instance.save()
          
        context = {
            'email': email,
            'status':"success"
            }

        Team.objects.filter(id='8').update(status=1)
        check_status_for_endpoint_user()
        check_status_if_all_submitted()

        data=Team.objects.get(id='8')

            #******************* Session Object Start *************************    

        asset_dlpI = request.session.get('asset_dlpI') 
        asset_dlpNI = request.session.get('asset_dlpNI') 
        asset_dlpU = request.session.get('asset_dlpU') 
        
        session_data_dict = {'Asset Management':{"Count of user system - Installed" : asset_dlpI,"Count of user system - Not Installed" : asset_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : asset_dlpU}
        }

        #******************* Session Object Start *************************  

        send_email(data.team,data.owner,session_data_dict) 
           

        return render(request ,'kriaApp/assetManage.html',context)
    return render(request ,'kriaApp/assetManage.html',context)


def patchManage(request):
    email = request.session.get('name') 
    context = {'email': email}

    # temp=Team.objects.get(id='11')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


    
    if 'rscdValidate' in request.POST:
        score_fields = ['dlpI', 'dlpNI', 'dlpU']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        dlpI=scores['dlpI']
        dlpNI=scores['dlpNI']
        dlpU=scores['dlpU']

        #******************* Session Object Start *************************    
        request.session['patch_dlpI']=dlpI
        request.session['patch_dlpNI']=dlpNI
        request.session['patch_dlpU']=dlpU

        #******************* Session Object Start *************************  

        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation
        #Rememeber here formula is 
        #dlpNI_per = dlpNI/totalserver count(windows+linux)
        dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
        dlpU_per = round(dlpU/dlpI,3)

        #weightage
        high_Score_ni= 0.08
        medium_Score_ni = 0.05
        low_Score_ni= 0.03

        high_Score_u = 0.08
        medium_Score_u = 0.05
        low_Score_u = 0.03


        #risk score calculation 
        dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

        dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

        #Fetch Previous month score
        last_entry = PatchManage.objects.latest('date')
        
        # last month risk score
        dlpNI_rs_last = last_entry.uninstalled_risk_score
        dlpU_rs_last = last_entry.unhealthy_risk_score

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
        dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
        dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
        dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
        color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
        color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
        color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'PatchManage',
            'email': email,

            'uninstalled':dlpNI_rs,
            'unhealthy':dlpU_rs,

            'uninstalled_last':dlpNI_rs_last,
            'unhealthy_last':dlpU_rs_last,

            'severity_last_NI':dlpNI_rs_severity_last,
            'severity_last_U':dlpU_rs_severity_last,
            'severity_current_NI':dlpNI_rs_severity,
            'severity_current_U':dlpU_rs_severity,

            'color_last_NI':color_dlpNI_rs_last,
            'color_current_NI':color_dlpNI_rs,
            'color_last_U':color_dlpU_rs__last,
            'color_current_U':color_dlpU_rs,
        }


        dlp_instances=PatchManage(
            installed = dlpI,
            uninstalled = dlpNI,
            unhealthy = dlpU,
            uninstalled_per = dlpNI_per,
            unhealthy_per =dlpU_per,
            uninstalled_risk_score = dlpNI_rs,
            unhealthy_risk_score = dlpU_rs,
            Evidence=save_path
        )

        dlp_instances.save()
       
        return render(request ,'kriaApp/patchManage.html',context)
    elif 'bsubmit' in request.POST:
        flag = request.POST.get('flag')
      
        ModelClass = apps.get_model('kriaApp', 'PatchManage')
     
        if flag == '1':
            uninstalled_justification=request.POST.get('uninstalled_justification')
            unhealthy_justification=request.POST.get('unhealthy_justification')
            latest_instance = ModelClass.objects.latest('date')
            latest_instance.uninstalled_justification = uninstalled_justification
            latest_instance.unhealthy_justification = unhealthy_justification
            latest_instance.save()
                
          
        context = {
            'email': email,
            'status':'success'
            }
        Team.objects.filter(id='11').update(status=1)
        check_status_for_endpoint_server()
        check_status_if_all_submitted()

        data=Team.objects.get(id='11')

          #******************* Session Object Start *************************    

        patch_dlpI = request.session.get('patch_dlpI') 
        patch_dlpNI = request.session.get('patch_dlpNI') 
        patch_dlpU = request.session.get('patch_dlpU') 
       
        session_data_dict = {'Patch Management Software':{"Server system with RSCD installed(Win+Linux+Solaries+CentOS)" : patch_dlpI,"Server system with RSCD not installed(Win+Linux+Solaries+CentOS)" : patch_dlpNI,"Server system unhealthy(including system not reporting)" : patch_dlpU}
        }

            #******************* Session Object Start *************************  

        send_email(data.team,data.owner,session_data_dict) 
       
        return render(request ,'kriaApp/patchManage.html',context)

    return render(request ,'kriaApp/patchManage.html',context)


def network(request):
    
    email = request.session.get('name') 
    context = {'email': email}
    
    # temp=Team.objects.get(id='10')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


    if 'networkSubmit' in request.POST:
        score_fields = ['total', 'critical', 'medium', 'n_mius_2_os']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        total = scores['total']
        critical = scores['critical']
        medium = scores['medium']
        n_mius_2_os = scores['n_mius_2_os']

        #******************* Session Object Start *************************    
        request.session['network_total']=total
        request.session['network_critical']=critical
        request.session['network_medium']=medium
        request.session['network_n_mius_2_os']=n_mius_2_os
      
        #******************* Session Object Start *************************  

              
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  

                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        
        
        critical_Percentage = round(critical/total,3)
        medium_Percentage = round(medium/total,3)
        n_mius_2_os_per=round(n_mius_2_os/total,3)

        high_Score = 0.8 
        medium_Score = 0.5
        low_Score = 0.3

        critical_and_high_rs = 4 if critical_Percentage > high_Score else (3 if critical_Percentage > medium_Score else (2 if critical_Percentage > low_Score else 1))
        medium_rs = 4 if medium_Percentage > high_Score else (3 if medium_Percentage > medium_Score else (2 if medium_Percentage > low_Score else 1))
        n_mius_2_os_rs= 4 if n_mius_2_os_per > high_Score else (3 if n_mius_2_os_per > medium_Score else (2 if n_mius_2_os_per > low_Score else 1))

        risk = [critical_and_high_rs, medium_rs ,n_mius_2_os_rs]  
        weightage = [0.1, 0.05 ,0.1] 

        # Calculate the sum product
        # appsec_risk_score = np.sum(np.array(weightage) * np.array(risk))

        #Fetch Previous month score
        last_entry = Network.objects.latest('date')
        
        # Access the fields of the last entry
        critical_and_high_rs_last = last_entry.critical_and_high_rs
        medium_rs_last = last_entry.medium_rs
        n_mius_2_os_rs_last = last_entry.n_mius_2_os_rs
      
        # print(appsec_critical_risk_score_previous)
        # print(appsec_High_Risk_Score_previous)
       
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        severity_critical_previous = severity_mapping.get(critical_and_high_rs_last, 'unknown')
        severity_medium_previous=severity_mapping.get(medium_rs_last, 'unknown')
        severity_nOS_previous=severity_mapping.get(n_mius_2_os_rs_last, 'unknown')

        severity_critical = severity_mapping.get(critical_and_high_rs, 'unknown')
        severity_medium=severity_mapping.get(medium_rs, 'unknown')
        severity_nOS=severity_mapping.get(n_mius_2_os_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # Example usage:
      
        color_class_critical_previous = map_severity_to_color(severity_critical_previous)
        color_class_medium_previous = map_severity_to_color(severity_medium_previous)
        color_class_nOS_previous = map_severity_to_color(severity_nOS_previous)

        color_class_critical = map_severity_to_color(severity_critical)
        color_class_medium = map_severity_to_color(severity_medium)
        color_class_nOS = map_severity_to_color(severity_nOS)
       

        context={
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'email':email,

            'critical_and_high_rs_last' :critical_and_high_rs_last,
            'medium_rs_last':medium_rs_last,
            'n_mius_2_os_rs_last':n_mius_2_os_rs_last,

            'critical_and_high_rs' :critical_and_high_rs,
            'medium_rs':medium_rs,
            'n_mius_2_os_rs':n_mius_2_os_rs,

            'severity_nOS_previous' :severity_nOS_previous,
            'severity_medium_previous':severity_medium_previous,
            'severity_critical_previous' :severity_critical_previous,
           
            'severity_nOS' :severity_nOS,
            'severity_medium':severity_medium,
            'severity_critical' :severity_critical,

            'color_class_critical_previous' :color_class_critical_previous,
            'color_class_medium_previous':color_class_medium_previous,
            'color_class_nOS_previous':color_class_nOS_previous,


            'color_class_critical' :color_class_critical,
            'color_class_medium':color_class_medium,
            'color_class_nOS':color_class_nOS,

        }
        

        appsec_instance = Network(
            Total=total,
            critical_and_high=critical,
            medium=medium,
            n_mius_2_os=n_mius_2_os ,

            critical_and_high_per=critical_Percentage ,
            medium_per=medium_Percentage ,
            n_mius_2_os_per=n_mius_2_os_per,

            critical_and_high_rs =critical_and_high_rs, 
            medium_rs = medium_rs,
            n_mius_2_os_rs=n_mius_2_os_rs,

          
            Evidence=save_path,

        )

        appsec_instance.save()
                        
        return render(request ,'kriaApp/network.html',context)
    elif 'validate' in request.POST:
        flag = request.POST.get('flag')
        if flag == '1':
            critical_and_high_rs_justification=request.POST.get('critical_and_high_rs_justification')
            medium_rs_justification=request.POST.get('medium_rs_justification')
            n_mius_2_os_justification=request.POST.get('n_mius_2_os_justification')

       
            # Get the latest instance of Appsec from the database
            latest_appsec_instance = Network.objects.latest('date')
            print(latest_appsec_instance)

            # Update the latest instance with the justifications
            latest_appsec_instance.critical_and_high_rs_justification = critical_and_high_rs_justification
            latest_appsec_instance.medium_rs_justification = medium_rs_justification
            latest_appsec_instance.n_mius_2_os_justification = n_mius_2_os_justification

          
            try:
                latest_appsec_instance.save()
            except Exception as e:
                print("Error while saving to the database:", str(e))
        
    
        context={
                'status':'success',
                'email': email
            }
        Team.objects.filter(id='10').update(status=1)
        check_status_if_all_submitted()


         #******************* Session Object Start *************************    

        network_total = request.session.get('network_total') 
        network_critical = request.session.get('network_critical') 
        network_medium = request.session.get('network_medium') 
        network_n_mius_2_os = request.session.get('network_n_mius_2_os') 

        session_data_dict = {'Network & Security Devices':{"Total Devices" : network_total,"Devices not patched with critical & high for more than 30 days" : network_critical,"Devices not patched with medium for more than 60 days" : network_medium,"Devices running n-2 OS version(n=current version of OS)" : network_n_mius_2_os}
        }

        data=Team.objects.get(id='10')
        send_email(data.team,data.owner,session_data_dict) 

        #******************* Session Object Start *************************  
       

        return render(request ,'kriaApp/network.html',context)

    return render(request ,'kriaApp/network.html',context)


def endpointInfra(request):
    email = request.session.get('name') 
    context = {'email': email}
    global tag3

    # temp=Team.objects.get(id='9')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


   
    if 'EncryptionValidate' in request.POST:
        score_fields = ['dlpI', 'dlpNI', 'dlpU']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
        dlpI=scores['dlpI']
        dlpNI=scores['dlpNI']
        dlpU=scores['dlpU']

        
        #******************* Session Object Start *************************    
        request.session['encryption_dlpI']=dlpI
        request.session['encryption_dlpNI']=dlpNI
        request.session['encryption_dlpU']=dlpU

        #******************* Session Object Start *************************  


        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  

                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        #Percentage Calculation
        dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
        dlpU_per = round(dlpU/dlpI,3)

        #weightage
        high_Score_ni= 0.15
        medium_Score_ni = 0.10
        low_Score_ni= 0.05

        high_Score_u = 0.10
        medium_Score_u = 0.08
        low_Score_u = 0.05


        #risk score calculation 
        dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

        dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))


        #Fetch Previous month score
        last_entry = Encryption.objects.latest('date')
        
        # last month risk score
        dlpNI_rs_last = last_entry.uninstalled_risk_score
        dlpU_rs_last = last_entry.unhealthy_risk_score

        # severity calculation
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
        dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
        dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
        dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'


        # color calculation
        color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
        color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
        color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
        color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

        
        context= {
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'team':'Encryption',

            'email': email,
            'uninstalled':dlpNI_rs,
            'unhealthy':dlpU_rs,
            'uninstalled_last':dlpNI_rs_last,
            'unhealthy_last':dlpU_rs_last,
            'severity_last_NI':dlpNI_rs_severity_last,
            'severity_last_U':dlpU_rs_severity_last,
            'severity_current_NI':dlpNI_rs_severity,
            'severity_current_U':dlpU_rs_severity,
            'color_last_NI':color_dlpNI_rs_last,
            'color_current_NI':color_dlpNI_rs,
            'color_last_U':color_dlpU_rs__last,
            'color_current_U':color_dlpU_rs,
        }


        dlp_instances=Encryption(
            installed = dlpI,
            uninstalled = dlpNI,
            unhealthy = dlpU,
            uninstalled_per = dlpNI_per,
            unhealthy_per =dlpU_per,
            uninstalled_risk_score = dlpNI_rs,
            unhealthy_risk_score = dlpU_rs,
            Evidence=save_path
        )

        dlp_instances.save()
        return render(request ,'kriaApp/endpointInfra.html',context)
    elif 'Vsubmit' in request.POST:
        flag = request.POST.get('flag')
        team=request.POST.get('team')
        ModelClass = apps.get_model('kriaApp', team)
        for i in tag3:
            print(i)
            if flag == '1':
                uninstalled_justification=request.POST.get('uninstalled_justification')
                unhealthy_justification=request.POST.get('unhealthy_justification')
                latest_instance = ModelClass.objects.latest('date')
                latest_instance.uninstalled_justification = uninstalled_justification
                latest_instance.unhealthy_justification = unhealthy_justification
                latest_instance.save()
            

            tag3.pop(0)
            context = {
                'email': email,
                'status':i
                }

            check_status_for_endpoint_user()
            check_status_for_endpoint_server()
            return render(request ,'kriaApp/endpointInfra.html',context)
    elif 'McAfeeAVUserValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'McAfeeAVUserValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']
           
           
            #******************* Session Object Start *************************    
            request.session['macfee_user_dlpI']=dlpI
            request.session['macfee_user_dlpNI']=dlpNI
            request.session['macfee_user_dlpU']=dlpU

            #******************* Session Object Start *************************  

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(name)
                os.makedirs(save_dir, exist_ok=True)  

                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)

            #Percentage Calculation
            dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
            dlpU_per = round(dlpU/dlpI,3)

            #weightage
            high_Score_ni= 0.15
            medium_Score_ni = 0.10
            low_Score_ni= 0.05

            high_Score_u = 0.10
            medium_Score_u = 0.08
            low_Score_u = 0.05

            #risk score calculation 
            dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

            dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

            #Fetch Previous month score
            last_entry =McAfeeAVUser.objects.latest('date')
            
            # last month risk score
            dlpNI_rs_last = last_entry.uninstalled_risk_score
            dlpU_rs_last = last_entry.unhealthy_risk_score

            # severity calculation
            severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
            dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
            dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
            dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

            def map_severity_to_color(severity):
                if severity == 'low':
                    return 'badge-success'
                elif severity == 'medium':
                    return 'badge-primary'
                elif severity == 'high':
                    return 'badge-warning'
                elif severity == 'critical':
                    return 'badge-danger'
                else:
                    return 'badge-secondary'


            # color calculation
            color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
            color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
            color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
            color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'validate',
                'team':'McAfeeAVUser',
                'email': email,
                'uninstalled':dlpNI_rs,
                'unhealthy':dlpU_rs,
                'uninstalled_last':dlpNI_rs_last,
                'unhealthy_last':dlpU_rs_last,
                'severity_last_NI':dlpNI_rs_severity_last,
                'severity_last_U':dlpU_rs_severity_last,
                'severity_current_NI':dlpNI_rs_severity,
                'severity_current_U':dlpU_rs_severity,
                'color_last_NI':color_dlpNI_rs_last,
                'color_current_NI':color_dlpNI_rs,
                'color_last_U':color_dlpU_rs__last,
                'color_current_U':color_dlpU_rs,
            }

            dlp_instances=McAfeeAVUser(
                installed = dlpI,
                uninstalled = dlpNI,
                unhealthy = dlpU,
                uninstalled_per = dlpNI_per,
                unhealthy_per =dlpU_per,
                uninstalled_risk_score = dlpNI_rs,
                unhealthy_risk_score = dlpU_rs,
                Evidence=save_path
            )

         
            dlp_instances.save()
            return render(request ,'kriaApp/endpointInfra.html',context)
    elif 'McAfeeAVServerValidate' in request.POST:
        email = request.session.get('name') 
        context = {'email': email}

        if 'McAfeeAVServerValidate' in request.POST:
            score_fields = ['dlpI', 'dlpNI', 'dlpU']
            scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
            dlpI=scores['dlpI']
            dlpNI=scores['dlpNI']
            dlpU=scores['dlpU']

            
             #******************* Session Object Start *************************    
            request.session['macfee_server_dlpI']=dlpI
            request.session['macfee_server_dlpNI']=dlpNI
            request.session['macfee_server_dlpU']=dlpU

            #******************* Session Object Start *************************    

            if request.method == 'POST' and request.FILES.get('fileInput'):
                uploaded_file = request.FILES['fileInput']
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                save_dir = os.path.join(static_dir, 'media')
                uploaded_image = uploaded_file
                name=uploaded_image.name
                # print(nameValidate)
                os.makedirs(save_dir, exist_ok=True)  

                save_path1 = os.path.join(save_dir, name)
                save_path = save_path1.split('/')
                save_path = '/'.join(save_path[6:])
                base_url = 'https://kritracker.npci.org.in/'
                save_path = base_url  + save_path

                # print(save_path)
                # Save the uploaded image to the specified path
                with open(save_path1, 'wb') as f:
                    for chunk in uploaded_image.chunks():
                        f.write(chunk)


          
            #Fetch Previous month score
            last_entry =McAfeeAVServer.objects.latest('date')
            total_last=last_entry.installed
        
            context= {
                'current_month_name' : current_month_name,
                'previous_month_name' : previous_month_name,
                'status':'avserver',
                'team':'McAfeeAVServer',
                'email': email,
                'total_last':total_last,
                'total':dlpI ,
            }

            dlp_instances=McAfeeAVServer(
                installed = dlpI,
                uninstalled = dlpNI,
                unhealthy = dlpU,
                Evidence=save_path
            )

            dlp_instances.save()
            return render(request ,'kriaApp/endpointInfra.html',context)
    # elif 'McAfeeDLPValidate' in request.POST:
    #     email = request.session.get('name') 
    #     context = {'email': email}

    #     if 'McAfeeDLPValidate' in request.POST:
    #         score_fields = ['dlpI', 'dlpNI', 'dlpU']
    #         scores = {field: int(request.POST.get(field, 0)) for field in score_fields}
    #         dlpI=scores['dlpI']
    #         dlpNI=scores['dlpNI']
    #         dlpU=scores['dlpU']

    #          #******************* Session Object Start *************************    
    #         request.session['macfee_dlp_dlpI']=dlpI
    #         request.session['macfee_dlp_dlpNI']=dlpNI
    #         request.session['macfee_dlp_dlpU']=dlpU

    #         #******************* Session Object Start *************************  
    #         if request.method == 'POST' and request.FILES.get('fileInput'):
    #             uploaded_file = request.FILES['fileInput']
    #             static_dir = os.path.join(os.path.dirname(__file__), 'static')
    #             save_dir = os.path.join(static_dir, 'media')
    #             uploaded_image = uploaded_file
    #             name=uploaded_image.name
    #             # print(name)
    #             os.makedirs(save_dir, exist_ok=True)  

    #             save_path1 = os.path.join(save_dir, name)
    #             save_path = save_path1.split('/')
    #             save_path = '/'.join(save_path[6:])
    #             base_url = 'https://kritracker.npci.org.in/'
    #             save_path = base_url  + save_path

    #             # print(save_path)
    #             # Save the uploaded image to the specified path
    #             with open(save_path1, 'wb') as f:
    #                 for chunk in uploaded_image.chunks():
    #                     f.write(chunk)


    #         #Percentage Calculation
    #         dlpNI_per = round(dlpNI/(dlpI+dlpNI),3)
    #         dlpU_per = round(dlpU/dlpI,3)

    #         #weightage
    #         high_Score_ni= 0.15
    #         medium_Score_ni = 0.10
    #         low_Score_ni= 0.05

    #         high_Score_u = 0.10
    #         medium_Score_u = 0.08
    #         low_Score_u = 0.05

    #         #risk score calculation 
    #         dlpNI_rs = 4 if dlpNI_per > high_Score_ni else (3 if dlpNI_per > medium_Score_ni else (2 if dlpNI_per > low_Score_ni else 1))

    #         dlpU_rs = 4 if dlpU_per > high_Score_u else (3 if dlpU_per > medium_Score_u else (2 if dlpU_per > low_Score_u else 1))

    #         #Fetch Previous month score
    #         last_entry =McAfeeDLP.objects.latest('date')
            
    #         # last month risk score
    #         dlpNI_rs_last = last_entry.uninstalled_risk_score
    #         dlpU_rs_last = last_entry.unhealthy_risk_score

    #         # severity calculation
    #         severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
    #         dlpNI_rs_severity_last = severity_mapping.get(dlpNI_rs_last, 'unknown')
    #         dlpU_rs_severity_last=severity_mapping.get(dlpU_rs_last, 'unknown')
    #         dlpNI_rs_severity = severity_mapping.get(dlpNI_rs, 'unknown')
    #         dlpU_rs_severity=severity_mapping.get(dlpU_rs, 'unknown')

    #         def map_severity_to_color(severity):
    #             if severity == 'low':
    #                 return 'badge-success'
    #             elif severity == 'medium':
    #                 return 'badge-primary'
    #             elif severity == 'high':
    #                 return 'badge-warning'
    #             elif severity == 'critical':
    #                 return 'badge-danger'
    #             else:
    #                 return 'badge-secondary'


    #         # color calculation
    #         color_dlpNI_rs_last = map_severity_to_color(dlpNI_rs_severity_last)
    #         color_dlpU_rs__last = map_severity_to_color(dlpU_rs_severity_last)
    #         color_dlpNI_rs= map_severity_to_color(dlpNI_rs_severity)
    #         color_dlpU_rs = map_severity_to_color(dlpU_rs_severity)

    #         context= {
    #             'current_month_name' : current_month_name,
    #             'previous_month_name' : previous_month_name,
    #             'status':'validate',
    #             'team':'McAfeeDLP',
    #             'email': email,
    #             'uninstalled':dlpNI_rs,
    #             'unhealthy':dlpU_rs,
    #             'uninstalled_last':dlpNI_rs_last,
    #             'unhealthy_last':dlpU_rs_last,
    #             'severity_last_NI':dlpNI_rs_severity_last,
    #             'severity_last_U':dlpU_rs_severity_last,
    #             'severity_current_NI':dlpNI_rs_severity,
    #             'severity_current_U':dlpU_rs_severity,
    #             'color_last_NI':color_dlpNI_rs_last,
    #             'color_current_NI':color_dlpNI_rs,
    #             'color_last_U':color_dlpU_rs__last,
    #             'color_current_U':color_dlpU_rs,
    #         }

    #         dlp_instances=McAfeeDLP(
    #             installed = dlpI,
    #             uninstalled = dlpNI,
    #             unhealthy = dlpU,
    #             uninstalled_per = dlpNI_per,
    #             unhealthy_per =dlpU_per,
    #             uninstalled_risk_score = dlpNI_rs,
    #             unhealthy_risk_score = dlpU_rs,
    #             Evidence=save_path
    #         )

    #         dlp_instances.save()
    #         return render(request ,'kriaApp/endpointInfra.html',context)
    elif 'V2submit' in  request.POST:
        context = {
                'email': email,
                'status':'success'
                }
        Team.objects.filter(id='9').update(status=1)

        check_status_for_endpoint_user()
        check_status_for_endpoint_server()
        check_status_if_all_submitted()

        data=Team.objects.get(id='9')


            
        #******************* Session Object Start *************************    

        encryption_dlpI = request.session.get('encryption_dlpI') 
        encryption_dlpNI = request.session.get('encryption_dlpNI') 
        encryption_dlpU = request.session.get('encryption_dlpU') 

        macfee_user_dlpI = request.session.get('macfee_user_dlpI') 
        macfee_user_dlpNI = request.session.get('macfee_user_dlpNI') 
        macfee_user_dlpU = request.session.get('macfee_user_dlpU') 
        
        macfee_server_dlpI = request.session.get('macfee_server_dlpI') 
        macfee_server_dlpNI = request.session.get('macfee_server_dlpNI') 
        macfee_server_dlpU = request.session.get('macfee_server_dlpU') 
        
        # macfee_dlp_dlpI = request.session.get('macfee_dlp_dlpI') 
        # macfee_dlp_dlpNI = request.session.get('macfee_dlp_dlpNI') 
        # macfee_dlp_dlpU = request.session.get('macfee_dlp_dlpU') 
        
       
        session_data_dict = {'Encryption - User System':{"Count of user system - Installed (laptop + Desktop)" : encryption_dlpI,"Count of user system - Not Installed (laptop + Desktop)" : encryption_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : encryption_dlpU},'McAfee AV Compliance - Server System':{"Count of user system - Installed (Win + Linux) " : macfee_server_dlpI,"Count of user system - Not Installed (Win + Linux)" : macfee_server_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : macfee_server_dlpU},'AV (McAfee) Compliance - User System ':{"Count of user system - Installed (laptop + Desptop)" : macfee_user_dlpI,"Count of user system - Not Installed (laptop + Desptop)" : macfee_user_dlpNI,"Count of user system - Unhealthy (including system not reporting)" : macfee_user_dlpU}}

        send_email(data.team,data.owner,session_data_dict) 

        #******************* Session Object Start *************************  

     
        return render(request ,'kriaApp/endpointInfra.html',context)

    return render(request ,'kriaApp/endpointInfra.html',context)


def securityAudit(request):
    email = request.session.get('name') 
    context = {'email': email ,}

    # temp=Team.objects.get(id='3')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

   
    
    if 'securityAuditSubmit' in request.POST:
        score_fields = ['total', 'critical',  'medium', 'low']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        appsec = scores['total']
        critical = scores['critical']
        medium = scores['medium']
        low = scores['low']

        #******************* Session Object Start *************************    
        request.session['audit_appsec']=appsec
        request.session['audit_critical']=critical
        request.session['audit_medium']=medium
        request.session['audit_low']=low

        #******************* Session Object Start *************************  

              
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  

                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        
        
        critical_Percentage = round(critical/appsec,3)
        medium_Percentage = round(medium/appsec,3)
        low_Percentage = round(low/appsec,3)

        high_Score = 0.3 
        medium_Score = 0.2
        low_Score = 0.15

        risk_score = 4 if critical_Percentage > high_Score else (3 if critical_Percentage > medium_Score else (2 if critical_Percentage > low_Score else 1))

        w_instance=Category.objects.get(name='Security Audit')
        name=w_instance.name
       
        r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.1
        )

        r_instance.save()


        #Fetch Previous month score
        last_entry = SecurityAudit.objects.latest('date')
        
        # Access the fields of the last entry
        risk_score_previous = last_entry.risk_score
       
          
        severity_mapping = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

        severity_critical_previous = severity_mapping.get(risk_score_previous, 'unknown')
     
        severity_critical_current=severity_mapping.get(risk_score, 'unknown')
        
        def map_severity_to_color(severity):
            if severity == 'low':
                return 'badge-success'
            elif severity == 'medium':
                return 'badge-primary'
            elif severity == 'high':
                return 'badge-warning'
            elif severity == 'critical':
                return 'badge-danger'
            else:
                return 'badge-secondary'

        # Example usage:
      
        color_class_critical_previous = map_severity_to_color(severity_critical_previous)
        color_class_critical_current = map_severity_to_color(severity_critical_current)


        context={
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',

            'risk_score' : risk_score,
            'risk_score_previous' :risk_score_previous,
        

            'severity_critical_previous' :severity_critical_previous,
            'severity_critical_current' :severity_critical_current,
          

            'color_class_critical_previous' :color_class_critical_previous,
            'color_class_critical_current':color_class_critical_current,

        }
        

        appsec_instance = SecurityAudit(
            total=appsec,
            critical=critical,
            medium=medium,
            low=low,

            critical_Percentage=critical_Percentage ,
            medium_Percentage=medium_Percentage,
            low_Percentage=low_Percentage,
            risk_score =risk_score, 
            Evidence=save_path,

        )

        appsec_instance.save()

        
                        
        return render(request ,'kriaApp/securityAudit.html',context)
    elif 'validate' in request.POST:
        flag = request.POST.get('flag')
        if flag == '1':
            critical_justification=request.POST.get('critical_justification')
       
            # Get the latest instance of Appsec from the database
            latest_appsec_instance = SecurityAudit.objects.latest('date')

            # Update the latest instance with the justifications
            latest_appsec_instance.critical_Justification = critical_justification

            try:
                latest_appsec_instance.save()
            except Exception as e:
                print("Error while saving to the database:", str(e))
        
            
        
        status='success'
        context={
                'status':status,
                'email': email
            }
        
        Team.objects.filter(id='3').update(status=1)
        check_status_if_all_submitted()

        data=Team.objects.get(id='3')

        #******************* Session Object Start *************************    

        audit_appsec = request.session.get('audit_appsec') 
        audit_critical = request.session.get('audit_critical') 
        audit_medium = request.session.get('audit_medium') 
        audit_low = request.session.get('audit_low') 

        session_data_dict = {'Security Audit':{"Total Observations" : audit_appsec,"Critical & High Points - Open" : audit_critical,"Medium Points - Open" : audit_medium,"Low Points - Open" : audit_low}
        }

        #******************* Session Object Start *************************  

        send_email(data.team,data.owner,session_data_dict) 


        return render(request ,'kriaApp/securityAudit.html',context)

    return render(request ,'kriaApp/securityAudit.html',context)


def ad(request):
    email = request.session.get('name') 
    context = {'email': email ,}

       
    # temp=Team.objects.get(id='14')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')

   
    
    if 'adSubmit' in request.POST:
        score_fields = ['wlaptop', 'wdesktop','llaptop', 'ldesktop','mlaptop', 'mdesktop',]
        # score_fields = ['laptop', 'desktop']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        wlaptop = scores['wlaptop']
        wdesktop = scores['wdesktop']
        llaptop = scores['llaptop']
        ldesktop = scores['ldesktop']
        mlaptop = scores['mlaptop']
        mdesktop = scores['mdesktop']

        #******************* Session Object Start *************************    
        request.session['wlaptop']=wlaptop
        request.session['wdesktop']=wdesktop
        request.session['llaptop']=llaptop
        request.session['ldesktop']=ldesktop
        request.session['mlaptop']=mlaptop
        request.session['mdesktop']=mdesktop
           

        #******************* Session Object Start *************************  



                  
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
            print(file_extension)

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
                print("Invlid")
                return render(request ,'kriaApp/login.html',context)
        

        Total_Desktop = wdesktop + ldesktop + mdesktop
        Total_Laptop = wlaptop + llaptop + mlaptop

        total = Total_Desktop + Total_Laptop

        #Fetch Previous month score
        last_entry = AD.objects.latest('date')
        
        # Access the fields of the last entry
        total_last = last_entry.Total
        context={
            'current_month_name' : current_month_name,
            'previous_month_name' : previous_month_name,
            'status':'validate',
            'total':total,
            'total_last':total_last,
        }
        appsec_instance = AD(
            Total=total,
            # Laptop=Laptop,
            # Desktop=Desktop,
            
            Total_Laptop= Total_Laptop,
            Total_Desktop = Total_Desktop ,
            lLaptop = llaptop ,
            lDesktop = ldesktop , 
            wLaptop = wlaptop ,
            wDesktop = wdesktop , 
            mLaptop = mlaptop ,
            mDesktop = mdesktop , 

            Evidence=save_path
        )
        appsec_instance.save()
        return render(request ,'kriaApp/ad.html',context)
    elif 'validate' in request.POST:
        status='success'
        context={
                'status':status,
                'email': email
            }
        Team.objects.filter(id='14').update(status=1)
        check_status_if_all_submitted()



         #******************* Session Object Start *************************    

        wlaptop = request.session.get('wlaptop') 
        wdesktop = request.session.get('wdesktop') 
        llaptop = request.session.get('llaptop') 
        ldesktop = request.session.get('ldesktop') 
        mlaptop = request.session.get('mlaptop') 
        mdesktop = request.session.get('mdesktop') 

        session_data_dict = {'Active Directory':{"Count of total windows laptops" : wlaptop,"Count of total windows desktops" : wdesktop,"Count of total linux laptops" : llaptop,"Count of total linux desktops" : ldesktop,"Count of total mac laptops" : mlaptop,"Count of total mac desktops" : mdesktop}
        }

        #******************* Session Object Start *************************  

        
        data=Team.objects.get(id='14')
        send_email(data.team,data.owner,session_data_dict) 
     

        return render(request ,'kriaApp/ad.html',context)
    return render(request ,'kriaApp/ad.html',context)


def raf(request):
    email = request.session.get('name') 
    context = {'email': email ,}

    temp=Team.objects.get(id='15')    

    if 'session' in request.session:
        if request.session['session']==0:
            return redirect('/')
    else:
        return redirect('/')


    
    if 'raf' in request.POST:
        score_fields = ['total', 'high', 'medium', 'low']
        scores = {field: int(request.POST.get(field, 0)) for field in score_fields}

        total = scores['total']
        high = scores['high']
        medium = scores['medium']
        low = scores['low']

        #******************* Session Object Start *************************    
        request.session['raf_total']=total
        request.session['raf_high']=high
        request.session['raf_medium']=medium
        request.session['raf_low']=low

        #******************* Session Object Start *************************  


              
        save_path ="" 
        if request.method == 'POST' and request.FILES.get('fileInput'):
            uploaded_file = request.FILES['fileInput']

            allowed_extensions = ['pdf' ,'xlsx' ,'xls' ,'csv' ,'txt' ,'jpg' ,'jpeg','png']

            file_extension = uploaded_file.name.split('.')[-1].lower()
          

            max_file_size = 25 * 1024 * 1024

            if file_extension in allowed_extensions:
                if uploaded_file.size <= max_file_size:
                    static_dir = os.path.join(os.path.dirname(__file__), 'static')
                    save_dir = os.path.join(static_dir, 'media')
                    uploaded_image = uploaded_file
                    name=uploaded_image.name
                    # print(name)
                    os.makedirs(save_dir, exist_ok=True)  
                    save_path1 = os.path.join(save_dir, name)
                    save_path = save_path1.split('/')
                    save_path = '/'.join(save_path[6:])
                    base_url = 'https://kritracker.npci.org.in/'
                    save_path = base_url  + save_path

                    # print(save_path)
                    # Save the uploaded image to the specified path
                    with open(save_path1, 'wb') as f:
                        for chunk in uploaded_image.chunks():
                            f.write(chunk)

                else:
                    messages.success(request, 'File size exceeds the allowed limit.')
                    return render(request ,'kriaApp/login.html',context)
            else:
                messages.success(request, 'Invalid File Type. Allowed file type: pdf, xlsx, xls, csv, txt, jpg, jpeg, png')
              
                return render(request ,'kriaApp/login.html',context)
        
        
        context = {
            'email': email ,
            'status':'success'
            }

        appsec_instance = RAF(
            total=total,
            high=high,
            medium=medium,
            low=low ,

            Evidence=save_path,

        )

        appsec_instance.save()
        Team.objects.filter(id='15').update(status=1)
        check_status_if_all_submitted()

        data=Team.objects.get(id='15')
       
         #******************* Session Object Start *************************    

        raf_total = request.session.get('raf_total') 
        raf_high = request.session.get('raf_high') 
        raf_medium = request.session.get('raf_medium') 
        raf_low = request.session.get('raf_low') 

        session_data_dict = {'RAF':{"Count of Total RAF Registered" : raf_total,"High Count" : raf_high,"Medium Count" : raf_medium,"Low Count" : raf_low}
        }

        #******************* Session Object Start *************************  

        send_email(data.team,data.owner,session_data_dict) 

                        
        return render(request ,'kriaApp/raf.html',context)
  
    
    return render(request ,'kriaApp/raf.html',context)


def endpointUserSystemRiskScore():

        #AV(McAfee) USer system  --Pratik
    temp=CB.objects.latest('date')
    cb_ninstalled=temp.cb_uninstalled_risk_score
    cb_unhealthy=temp.cb_unhealthy_risk_score

        #AMS USer system   ---- Darwin
    temp=AssetManagment.objects.latest('date')
    am_ninstalled=temp.uninstalled_risk_score
    am_unhealthy=temp.unhealthy_risk_score

        #NAC USer system  ----Venket 
    temp=NAC.objects.latest('date')
    nac_ninstalled=temp.nac_uninstalled_risk_score
    nac_unhealthy=temp.nac_unhealthy_risk_score
 
        #APT HX USer system  --Venket 
    temp=Sentinel.objects.latest('date')
    apt_ninstalled=temp.apt_uninstalled_risk_score
    apt_unhealthy=temp.apt_unhealthy_risk_score

        #McAfee Proxy USer system  ---Venket
    temp=McAfee.objects.latest('date')
    proxy_ninstalled=temp.mcafee_uninstalled_risk_score
    proxy_unhealthy=temp.mcafee_unhealthy_risk_score


          #Encryption USer system  ---Pratik
    temp=Encryption.objects.latest('date')
    encryption_ninstalled=temp.uninstalled_risk_score
    encryption_unhealthy=temp.unhealthy_risk_score


      #Forcepoint DLP USer system  --venkat 
    temp=DLP.objects.latest('date')
    f_ninstalled=temp.dlp_uninstalled_risk_score
    f_unhealthy=temp.dlp_unhealthy_risk_score


    risk=[f_unhealthy,f_ninstalled,encryption_unhealthy,encryption_ninstalled,proxy_unhealthy,proxy_ninstalled,apt_unhealthy,apt_ninstalled,nac_unhealthy,am_unhealthy,am_ninstalled,am_ninstalled,cb_unhealthy,cb_ninstalled]

    weightage = [
        0.07150, 0.07150, 
        0.07150, 0.07150,
        0.07150, 0.07150,
        0.07150,0.07150,
        0.07150,0.07150,
        0.07150, 0.07150, 
        0.07150, 0.07150,
      ] 
 
    risk_score = np.sum(np.array(weightage) * np.array(risk))


    w_instance=Category.objects.get(name='Endpoint USER System')
    name=w_instance.name
       
    r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.05
        )

    r_instance.save()


def endpointServerSystemRiskScore():
    vdi_rs_av_ninstalled=1
    vdi_rs_av_unhealthy=1
    vdi_rs_fireye_uninstalled=1
    vdi_rs_fireeye_unhealthy=1

    
    #Venket + Rakesh  (AV)
    temp=CB.objects.latest('date')
    av_rs_ninstalled=temp.cb_uninstalled_risk_score
    av_rs_unhealthy=temp.cb_unhealthy_risk_score

    #Patch Managemnet Software -- janardhan
    temp=PatchManage.objects.latest('date')
    ams_rs_ninstalled=temp.uninstalled_risk_score
    ams_rs_unhealthy=temp.unhealthy_risk_score

    #APT HX Server  --Venket
    temp=HX.objects.latest('date')
    apt_rs_ninstalled=temp.hx_uninstalled_risk_score
    apt_rs_unhealthy=temp.hx_unhealthy_risk_score


    risk = [vdi_rs_av_ninstalled, vdi_rs_av_unhealthy, vdi_rs_fireye_uninstalled ,vdi_rs_fireeye_unhealthy ,av_rs_ninstalled ,av_rs_unhealthy,ams_rs_ninstalled ,ams_rs_unhealthy,apt_rs_ninstalled,apt_rs_unhealthy]

    weightage = [0.10, 0.10, 0.10, 0.10, 0.10, 0.10,0.10,0.10,0.10,0.10] 
 
    risk_score = np.sum(np.array(weightage) * np.array(risk))


    w_instance=Category.objects.get(name='Endpoint Server System')
    name=w_instance.name
    
    r_instance=RiskScore(
            kri=w_instance,
            month=current_month_name,
            riskScore=risk_score,
            weightage=0.05
        )

    r_instance.save()


def get_severity_color(risk_score_severity):
    if risk_score_severity <= 1.99:
        return 'badge-success'
    elif risk_score_severity <=2.99:
        return 'badge-warning'
    elif risk_score_severity <=3.99:
        return 'badge-danger'


def check_status_for_endpoint_user():
    temp1=Team.objects.get(id='8')
    temp2=Team.objects.get(id='1')
    temp3=Team.objects.get(id='9')

    
    if temp1.status ==True and temp2.status == True and temp3.status == True:
        endpointUserSystemRiskScore()
  

def check_status_for_endpoint_server():
    temp1=Team.objects.get(id='11')
    temp2=Team.objects.get(id='1')
    temp3=Team.objects.get(id='9')

    if temp1.status ==True and temp2.status == True and temp3.status == True:
        endpointServerSystemRiskScore()


def calculate_totalrisk_score():
    data=RiskScore.objects.filter(month=current_month_name)

    f_score=0

    for item in data:
        f_score =f_score + (item.weightage * round(item.riskScore,2))

    r_instance=FinalRiskScore(
            month=current_month_name,
            riskScore=round(f_score,2)
        )

    r_instance.save()
    


def check_status_if_all_submitted():
    temp1=Team.objects.get(id='1')
    temp2=Team.objects.get(id='2')
    temp3=Team.objects.get(id='3')
    temp4=Team.objects.get(id='4')
    temp6=Team.objects.get(id='6')
    temp7=Team.objects.get(id='7')
    temp8=Team.objects.get(id='8')
    temp9=Team.objects.get(id='9')
    temp10=Team.objects.get(id='10')
    temp11=Team.objects.get(id='11')
    temp12=Team.objects.get(id='12')
    temp14=Team.objects.get(id='14')
    temp15=Team.objects.get(id='15')

    if temp1.status ==True and temp2.status == True and temp3.status == True and temp4.status == True and temp6.status == True and temp7.status == True and temp8.status == True and temp9.status == True and temp10.status == True and temp11.status == True and temp12.status == True and temp14.status == True and temp15.status == True:
        calculate_totalrisk_score()
       


def send_email(application_name,application_owner,session_data_dict):
    sender_email = "watchtower.elite@npci.org.in"

    print(application_name)
    print(application_owner)

    req_email =application_owner+'@npci.org.in'
 
    receiver_email = [req_email]

    #cc_email = ['satya.kanungo@npci.org.in', 'sandeep.tiwari@npci.org.in', 'ravi.krishna@npci.org.in', 'shweta.dwivedi@npci.org.in' ,'meenakshi.kharwade@npci.org.in']

    receiver_email =['ashishk.gupta@npci.org.in']
    cc_email =['ashishk.gupta@npci.org.in']

    subject = "Acknowledgement : Submission Received for KTRACK"

    # Create the MIME object
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = ', '.join(receiver_email)
    msg['Cc'] = ', '.join(cc_email)
    msg['Subject'] = subject


    body_html=f"""
     <html>
        <body>
            <p>Dear @{application_owner},</p>
            <p>This is to inform you that we have received your submission for {application_name} .</p>
            <p>Click on below link to view historical data.</p>
            <p>https://kritracker.npci.org.in/admin</p>
          
            """

    # Iterate over the session_data_dict
    for key, value in session_data_dict.items():
        session_data_table = f"<p>{key}:</p>"
        session_data_table += "<table border='1'>"
        for inner_key, inner_value in value.items():
            session_data_table += f"<tr><td>{inner_key}</td><td>{inner_value}</td></tr>"
        session_data_table += "</table>"
        body_html += session_data_table

    body_html += """




            <p>In case of any queries please reach out to meenakshi.kharwade@npci.org.in.</p>
            <p>Thanks & Regards,<br>Team Watchtower Elite</p>
        </body>
    </html>
    """

    msg.attach(MIMEText(body_html,'html'))

   

    all_receivers = receiver_email + cc_email
    server = smtplib.SMTP("10.98.0.126", 587)
    server.sendmail(sender_email, all_receivers , msg.as_string())
    print("Mail Send")
    server.quit()



def disable(request):
    Team.objects.filter(id='1').update(status=0) 
    Team.objects.filter(id='2').update(status=0) 
    Team.objects.filter(id='3').update(status=0) 
    Team.objects.filter(id='4').update(status=0) 
    Team.objects.filter(id='5').update(status=0) 
    Team.objects.filter(id='6').update(status=0) 
    Team.objects.filter(id='7').update(status=0) 
    Team.objects.filter(id='8').update(status=0) 
    Team.objects.filter(id='9').update(status=0) 
    Team.objects.filter(id='10').update(status=0) 
    Team.objects.filter(id='11').update(status=0) 
    Team.objects.filter(id='12').update(status=0) 
    Team.objects.filter(id='14').update(status=0) 
    Team.objects.filter(id='15').update(status=0) 

    return HttpResponse("Status disabled for all the forms !")

           
      
