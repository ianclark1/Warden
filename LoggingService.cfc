<cfcomponent displayname="Logger Utility" output="false">
	<cffunction name="init" access="public" output="false" returntype="warden.LoggingService">
		<cfargument name="logName" type="string" required="true" />
		<cfset variables.logName = arguments.logName />
		<cfreturn this />
	</cffunction>

	<cffunction name="info" access="public" output="no" returntype="void">
		<cfargument name="logtext" required="true">

		<cflog file="#variables.logName#" type="info" text="#arguments.logtext#">
	</cffunction>

	<cffunction name="error" access="public" output="no" returntype="void">
		<cfargument name="caughtError" required="true">

		<cfloop collection="#arguments.caughtError#" item="errorKey">
			<cfif isSimpleValue(arguments.caughtError[errorKey])>
				<cflog file="#variables.logName#" type="error" text="#errorKey#: #arguments.caughtError[errorKey]#">
			</cfif>
		</cfloop>
	</cffunction>
</cfcomponent>