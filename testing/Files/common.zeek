@load logschema

# Ensure that the current working directory gets removed from
# any script locations the schema generator identifies.
redef Log::Schema::script_prefixes += cat(getenv("PWD"), "/");
