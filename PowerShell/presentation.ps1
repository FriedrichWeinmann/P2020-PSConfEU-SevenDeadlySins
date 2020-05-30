# Failsafe
return










 #----------------------------------------------------------------------------# 
 #                        7. Forcing interactive mode                         # 
 #----------------------------------------------------------------------------# 

# Living in Sin
code "$filesRoot\example_7_InteractiveMode.ps1"

<#
Issues:
- Not Automatable
- hard to reuse
#>

# Fixing it
code "$filesRoot\example_7_InteractiveMode_edited.ps1"


 #----------------------------------------------------------------------------# 
 #                             6. Hardcoding Data                             # 
 #----------------------------------------------------------------------------# 

# Living in Sin
code "$filesRoot\example_6_HardcodingData.ps1"

<#
Issues:
- Hard to reuse
- Hard to track
- Hard to update
#>

# Fixing it
code "$filesRoot\example_6_HardcodingData_edited.ps1"


 #----------------------------------------------------------------------------# 
 #                           5. The One Long Script                           # 
 #----------------------------------------------------------------------------# 

# The Heretic
code "$filesRoot\example_5_TheOneLongScript.ps1"

<#
Issues:
- Hard to reuse
- Incredibly expensive to maintain / fix / upgrade
#>

# Redeeming a lost soul
code "$filesRoot\example_5_TheOneLongScript_edited.ps1"
# VSCode Autoformat: SHIFT + ALT + F

code "$filesRoot\example_5_TheOneLongScript_redeemed.ps1"


 #----------------------------------------------------------------------------# 
 #                              4. Breaking Bad                               # 
 #----------------------------------------------------------------------------# 

# The sin of Exit
#------------------

# Act of treason
code "$filesRoot\example_4_BreakingBad_exit.ps1"

<#
Issues:
- Kills the console for no good reason
#>

# The Cure
code "$filesRoot\example_4_BreakingBad_exit_edited.ps1"


# The sin of Break & Continue
#------------------------------

# Don't do it, Jim!
code "$filesRoot\example_4_BreakingBad_break.ps1"

<#
Issues:
- Incredibly hard to troubleshoot
- Breaks other people's code ... silently!
- Adds pure chaos
- Kills kittens
#>

# Path to salvation
code "$filesRoot\example_4_BreakingBad_break_edited.ps1"


 #----------------------------------------------------------------------------# 
 #                      3. Confusing Message with Output                      # 
 #----------------------------------------------------------------------------# 

# The Path of the Puppykiller
code "$filesRoot\example_3_KillingPuppies.ps1"

<#
Issues:
- Limits reusability
- Hard to automate
- Error prone
- Hard to debug
#>

# Love thy canine
code "$filesRoot\example_3_KillingPuppies_edited.ps1"


# More guidance:
# https://allthingspowershell.blogspot.com/2017/12/puppycide-done-right-output-versus.html

 #----------------------------------------------------------------------------# 
 #                      2. Violating the Scope Boundary                       # 
 #----------------------------------------------------------------------------# 

# Death to Kittens!
code "$filesRoot\example_2_ViolatingTheScopeBondary.ps1"

<#
Issues:
- Hard to read
- Expensive to maintain
- Very fragile against future changes
- Hard to reuse
#>

# Way too cute to hurt
code "$filesRoot\example_2_ViolatingTheScopeBondary_edited.ps1"
code "$filesRoot\example_2_ViolatingTheScopeBondary_compromise.ps1"


 #----------------------------------------------------------------------------# 
 #              1. Dynamic Parameters for Dynamic Tab Completion              # 
 #----------------------------------------------------------------------------# 

# Selling your soul to the Devil
code "$filesRoot\example_1_TheUltimateSin.ps1"

<#
Issues:
- Utterly Evil
- Unstable
- Bad User Experience when it breaks ("Unknown Parameter")
- Bad User Experience when it works
- No Parameter Help*
- End of the tab order
- All dynamic parameters are alphabetically sorted when it comes to tabbing
- Expensive to maintain
- Hard to read
- Reduce function readability
- Time intensive to write
- There are incredibly superior solutions at a fraction of the implementation overhead
#>

# What better choices you could have made
code "$filesRoot\example_1_WhatYouCouldHaveDoneInstead.ps1"