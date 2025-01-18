# login: auth account password session                                          
auth        sufficient      pam_smartcard.so     
auth        sufficient      pam_p11.so                                   
auth        optional        pam_krb5.so use_kcminit                               
auth        optional        pam_ntlm.so try_first_pass                            
auth        optional        pam_mount.so try_first_pass                           
auth        required        pam_opendirectory.so try_first_pass                   
auth        required        pam_deny.so                                           
account     required        pam_nologin.so                                        
account     required        pam_opendirectory.so                                  
password    required        pam_opendirectory.so                                  
session     required        pam_launchd.so                                        
session     required        pam_uwtmp.so                                          
session     optional        pam_mount.so
