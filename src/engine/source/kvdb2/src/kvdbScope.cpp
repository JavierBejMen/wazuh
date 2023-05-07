#include <kvdb2/kvdbScope.hpp>

namespace kvdbManager
{

KVDBScope::KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name)
    : m_handlerManager(handlerManager)
{
    setName(name);
}

bool KVDBScope::initialize()
{
    m_initialized = true;
    return m_initialized;
}

std::shared_ptr<IKVDBHandler> KVDBScope::getKVDBHandler(const std::string& dbName)
{
    return m_handlerManager->getKVDBHandler(dbName, getName());
}

} // namespace kvdbManager
