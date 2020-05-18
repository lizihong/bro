// See the file  in the main distribution directory for copyright.

#include "Syslog.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Syslog {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("Syslog", ::analyzer::syslog::Syslog_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::Syslog";
		config.description = "Syslog analyzer UDP-only";
		return config;
		}
} plugin;

}
}
