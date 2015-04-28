<!--- 
Copyright 2010 Steve Brownlee

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


    Name         : Warden
    Author       : Steve Brownlee
    Purpose      : Challenge user privileges based on actions
	Version      : 0.1.1

 --->

<cfcomponent displayname="Warden" hint="Determines if a user has access to functionality based on their role" output="false">

	<cffunction name="init" access="public" output="false" returntype="warden.Warden">
		<cfargument name="challengeDefinitionFile" type="string" required="false" default="" />
		
		<cfset variables.wardenDefinition = "" />
		<cfset variables.loggingService = createObject("component", "warden.LoggingService") />
		
		<cfif arguments.challengeDefinitionFile neq "" >
			<cfset loadChallengesFromXmlFile(arguments.challengeDefinitionFile) />
		</cfif>
		
		<cfreturn this />
	</cffunction>

	<cffunction name="challenge" displayname="Challenge" 
				hint="Challenges the user's ability to execute functionality" 
				access="public" output="true" returntype="boolean">
		<cfargument name="action" type="string" hint="The name of the action to be challenged" required="true" />
		<cfargument name="userPrivileges" type="string" required="true" hint="The list of privileges assigned to the user" />
		<cfargument name="viewState" type="string" required="false" default="default" hint="An optional parameter that describes the current view state" />
		<cfargument name="type" type="string" required="false" default="EXCLUSIVE" hint="INCLUSIVE or EXCLUSIVE challenge type. Inclusive to ensure user has all privileges, and exclusive if the user only needs one privilege. (default=EXCLUSIVE)" />
		<cfargument name="debug" type="boolean" required="false" default="false" hint="An optional parameter that will output debug information to the application log file (default=false)" />
		
		<cfset var local = structNew() />
		<cfset local.privilegeMatch = false />
		<cfset local.debugMsg = "" />
		<cfset local.challengeExists = false />
		<cfset local.viewStateExists = false />
		<cfset local.challengeArray = variables.wardenDefinition.challenges.challenge />
		
        <!--- Use the application attribute of the challenges element as the name of the log file --->
		<cfif structKeyExists(variables.wardenDefinition.challenges.XmlAttributes, "application")>
			<cfset variables.loggingService.init(variables.wardenDefinition.challenges.XmlAttributes.application) />
		<cfelse>
			<cfthrow type="warden.MalformedWardenDefinition" 
					message="You must specify an application attribute of the challenges element in your Warden definition file.">
		</cfif>
		
		<cfloop from="1" to="#arrayLen(local.challengeArray)#" index="chIx">
			<cfset local.challengeAttributes = local.challengeArray[chIx].XmlAttributes />
			
			<cfif structKeyExists(local.challengeAttributes, "id")>
				<cfif local.challengeAttributes.id eq arguments.action>

				    <cfset variables.loggingService.info("Warden: Challenge " & arguments.action & " found") />
				    <cfset local.challengeExists = true />

                    <!--- Extract all allowedPrivilege elements in the challenge --->
					<cfset local.allowedPrivileges = local.challengeArray[chIx].allowedPrivileges />

					<!--- Loop through all the allowedPrivileges for this challenge definition --->
					<cfloop from="1" to="#arrayLen(local.allowedPrivileges)#" index="privIx">

						<!--- Determine if there is a viewState condition on this privilege challenge --->
						<cfif structKeyExists(local.allowedPrivileges[privIx], "XmlAttributes") and 
								structKeyExists(local.allowedPrivileges[privIx].XmlAttributes, "viewstate")>
							<cfset local.viewState = local.allowedPrivileges[privIx].XmlAttributes.viewState />
							
						<!--- If no viewState specified in config file, set to 'default' --->
						<cfelse>
							<cfset local.viewState = "default" />
						</cfif>
						
						<!--- Check if the current viewState matches the challenge --->
						<cfif local.viewState eq arguments.viewState>
						
						    <cfset local.viewStateExists = true />
							<cfset local.privileges = local.allowedPrivileges[privIx].privilege />
	
							<!--- Loop through all the privileges for this challenge definition --->
							<cfloop from="1" to="#arrayLen(local.privileges)#" index="pIx">
							
								<!--- Verify that each privilege element has a value --->
								<cfif structKeyExists(local.privileges[pIx], "XmlName")>
		
									<!--- Loop through the user's privileges to find a match with the challenge privilege --->
									<cfloop from="1" to="#listLen(arguments.userPrivileges)#" index="uprivIx">
		
									    <!--- Check if the current user privilege matches the current challenge privilege --->
										<cfif trim(listGetAt(arguments.userPrivileges,uprivIx)) eq trim(local.privileges[pIx].XmlText)>
		
											<cfset variables.loggingService.info("Warden: User privilege list contains matching privilege - " & trim(local.privileges[pIx].XmlText)) />
											<cfset local.privilegeMatch = true />
											
											<!--- Found a privilege match. If this is an EXCLUSIVE challenge, we can return true immediately --->
											<cfif arguments.type eq "EXCLUSIVE">
                                                <cfreturn true />
											</cfif>

										<cfelse>

										    <!--- If this is an INCLUSIVE challenge, then on the first failed check, return false --->
										    <cfif arguments.type eq "INCLUSIVE">
												<cfset variables.loggingService.info("Warden: **CHALLENGE FAILED** User does not have one of the inclusive set of privileges - " & trim(local.privileges[pIx].XmlText)) />
											    <cfreturn false />
											</cfif>
		
										</cfif>
		
									</cfloop>
		
								<cfelse>
		
									<cfthrow type="warden.MalformedChallengeException" 
										message="Every privilege element in the allowedPrivileges list must contain a value.">
		
								</cfif>
							</cfloop>
						</cfif>
					</cfloop>
				</cfif>
			<cfelse>
				<cfthrow type="warden.MalformedChallengeException" 
					message="Challenge definitions must contain an 'id' attribute.">
			</cfif>
		</cfloop>

        <!--- Create log entry if challenge was not found --->
        <cfif not local.challengeExists>
            <cfset variables.loggingService.info("Warden: **CHALLENGE FAILED** The specified challenge - " & arguments.action & " - does not exist in definition file") />
        
        <!--- Create log entry if view state was not found --->
        <cfelseif not local.viewStateExists>
            <cfset variables.loggingService.info("Warden: **CHALLENGE FAILED** The specified viewstate - " & arguments.viewState & " - does not exist in definition file") />
        
        <!--- Log privilege failure message --->
        <cfelseif not local.privilegeMatch>
            <cfset variables.loggingService.info("Warden: **CHALLENGE FAILED** User privilege list did not contain any of the required privileges") />
        </cfif>
        
		<cfreturn local.privilegeMatch />
	</cffunction>

	<cffunction name="loadChallengesFromXmlFile" returntype="void" access="public" hint="Loads challenge definitions from an xml file location">
		<cfargument name="challengeDefinitionFile" type="string" required="true" hint="I am the location of the challenge definition xml file"/>
	
		<cfset var local = structNew() />
		
		<cftry>

    		<cfif not fileExists(arguments.challengeDefinitionFile)>
    			<cfset arguments.challengeDefinitionFile = expandPath(arguments.challengeDefinitionFile)>
    		</cfif>

    		<cfif not fileExists(arguments.challengeDefinitionFile)>
                <cfset variables.loggingService.init("warden") />

       			<cfthrow message="The file #arguments.challengeDefinitionFile# does not exist!"
					detail="You have tried to use or include a file (#arguments.challengeDefinitionFile#) that does not exist using either absolute, relative, or mapped paths." />
    		</cfif>
    	    <cfcatch type="any">
                <cfset variables.loggingService.error(cfcatch) />
				<cfrethrow />
    		</cfcatch>
		</cftry>
		
		<cffile action="read" file="#arguments.challengeDefinitionFile#" variable="local.fileContent" />

		<cfset variables.wardenDefinition = xmlParse(local.fileContent)>
	</cffunction>
	
	<cffunction name="getWardenDefinition" access="public" returntype="Any" output="false">
		<cfreturn variables.wardenDefinition />
	</cffunction>

</cfcomponent>