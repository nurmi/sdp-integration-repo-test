fields{
    required{
        cred = String 
    }
    optional{
        anchore_engine_url = String
	image_wait_timeout = int
	archive_only = Boolean
	bail_on_fail = Boolean
	policy_bundle = String
    }
}
