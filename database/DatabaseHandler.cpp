#include "DatabaseHandler.hpp"

#include "AudioTypes.hpp"
#include "FileTypes.hpp"


DatabaseHandler::DatabaseHandler(boost::filesystem::path db)
:
_path(db),
_dbBackend( db.string() )
{
	_session.setConnection(_dbBackend);
	_session.mapClass<Database::Genre>("genre");
	_session.mapClass<Database::Track>("track");
	_session.mapClass<Database::Artist>("artist");
	_session.mapClass<Database::Release>("release");
	_session.mapClass<Database::Release>("release");
	_session.mapClass<Database::Path>("path");
	_session.mapClass<Database::Video>("video");

	try {
	        _session.createTables();
	}
	catch(std::exception& e) {
		std::cerr << "Cannot create tables: " << e.what() << std::endl;
	}

	_dbBackend.executeSql("pragma journal_mode=WAL");
}

