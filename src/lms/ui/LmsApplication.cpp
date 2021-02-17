/*
 * Copyright (C) 2018 Emeric Poupon
 *
 * This file is part of LMS.
 *
 * LMS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LMS.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "LmsApplication.hpp"

#include <Wt/WAnchor.h>
#include <Wt/WEnvironment.h>
#include <Wt/WLineEdit.h>
#include <Wt/WPopupMenu.h>
#include <Wt/WPushButton.h>
#include <Wt/WServer.h>
#include <Wt/WStackedWidget.h>
#include <Wt/WText.h>

#include "auth/IEnvService.hpp"
#include "auth/IPasswordService.hpp"
#include "cover/ICoverArtGrabber.hpp"
#include "database/Artist.hpp"
#include "database/Cluster.hpp"
#include "database/Db.hpp"
#include "database/Release.hpp"
#include "database/Session.hpp"
#include "database/User.hpp"
#include "utils/Logger.hpp"
#include "utils/Service.hpp"
#include "utils/String.hpp"

#include "admin/InitWizardView.hpp"
#include "admin/DatabaseSettingsView.hpp"
#include "admin/UserView.hpp"
#include "admin/UsersView.hpp"
#include "explore/Explore.hpp"
#include "explore/Filters.hpp"
#include "resource/AudioFileResource.hpp"
#include "resource/AudioTranscodeResource.hpp"
#include "resource/DownloadResource.hpp"
#include "resource/CoverResource.hpp"
#include "Auth.hpp"
#include "LmsApplicationException.hpp"
#include "LmsTheme.hpp"
#include "MediaPlayer.hpp"
#include "PlayQueue.hpp"
#include "SettingsView.hpp"

namespace UserInterface {

static constexpr const char* defaultPath {"/releases"};

std::unique_ptr<Wt::WApplication>
LmsApplication::create(const Wt::WEnvironment& env, Database::Db& db, LmsApplicationGroupContainer& appGroups)
{
	return std::make_unique<LmsApplication>(env, db, appGroups);
}

LmsApplication*
LmsApplication::instance()
{
	return reinterpret_cast<LmsApplication*>(Wt::WApplication::instance());
}

Database::Session&
LmsApplication::getDbSession()
{
	return _db.getTLSSession();
}

Wt::Dbo::ptr<Database::User>
LmsApplication::getUser()
{
	if (!_userId)
		return {};

	return Database::User::getById(getDbSession(), *_userId);
}

bool
LmsApplication::isUserAuthStrong() const
{
	return *_userAuthStrong;
}

bool
LmsApplication::isUserAdmin()
{
	auto transaction {getDbSession().createSharedTransaction()};

	return getUser()->isAdmin();
}

bool
LmsApplication::isUserDemo()
{
	auto transaction {getDbSession().createSharedTransaction()};

	return getUser()->isDemo();
}

std::string
LmsApplication::getUserLoginName()
{
	auto transaction {getDbSession().createSharedTransaction()};

	return getUser()->getLoginName();
}

LmsApplication::LmsApplication(const Wt::WEnvironment& env,
		Database::Db& db,
		LmsApplicationGroupContainer& appGroups)
: Wt::WApplication {env},
  _db {db},
  _appGroups {appGroups}
{
	try
	{
		init();
	}
	catch (LmsApplicationException& e)
	{
		LMS_LOG(UI, WARNING) << "Caught a LmsApplication exception: " << e.what();
		handleException(e);
	}
	catch (std::exception& e)
	{
		LMS_LOG(UI, ERROR) << "Caught exception: " << e.what();
		throw LmsException {"Internal error"}; // Do not put details here at it may appear on the user rendered html
	}
}

LmsApplication::~LmsApplication() = default;

void
LmsApplication::init()
{
	useStyleSheet("resources/font-awesome/css/font-awesome.min.css");

	// Add a resource bundle
	messageResourceBundle().use(appRoot() + "admin-database");
	messageResourceBundle().use(appRoot() + "admin-initwizard");
	messageResourceBundle().use(appRoot() + "admin-scannercontroller");
	messageResourceBundle().use(appRoot() + "admin-user");
	messageResourceBundle().use(appRoot() + "admin-users");
	messageResourceBundle().use(appRoot() + "artist");
	messageResourceBundle().use(appRoot() + "artists");
	messageResourceBundle().use(appRoot() + "error");
	messageResourceBundle().use(appRoot() + "explore");
	messageResourceBundle().use(appRoot() + "login");
	messageResourceBundle().use(appRoot() + "mediaplayer");
	messageResourceBundle().use(appRoot() + "messages");
	messageResourceBundle().use(appRoot() + "playqueue");
	messageResourceBundle().use(appRoot() + "release");
	messageResourceBundle().use(appRoot() + "releases");
	messageResourceBundle().use(appRoot() + "search");
	messageResourceBundle().use(appRoot() + "settings");
	messageResourceBundle().use(appRoot() + "templates");
	messageResourceBundle().use(appRoot() + "tracks");

	// Require js here to avoid async problems
	requireJQuery("js/jquery-1.10.2.min.js");
	require("js/bootstrap-notify.js");
	require("js/bootstrap.min.js");
	require("js/mediaplayer.js");

	setTitle("LMS");

	// Handle Media Scanner events and other session events
	enableUpdates(true);

	if (Service<::Auth::IEnvService>::exists())
		processEnvAuth();
	else if (Service<::Auth::IPasswordService>::exists())
		processPasswordAuth();
	else
		throw LmsException {"Not auth service available!"};
}

void
LmsApplication::processEnvAuth()
{
	const auto checkResult {Service<::Auth::IEnvService>::get()->processEnv(getDbSession(), wApp->environment())};
	if (checkResult.state != ::Auth::IEnvService::CheckResult::State::Granted)
		throw LmsException {"Cannot extract user from environment!"};

	_userId = *checkResult.userId;
	onUserLoggedIn();
}

void
LmsApplication::processPasswordAuth()
{
	const auto checkResult {Service<::Auth::IPasswordService>::get()->processRememberMe(getDbSession(), *this)};
	if (checkResult.state == ::Auth::IPasswordService::CheckResult::State::Granted)
	{
		_userId = *checkResult.userId;
		onUserLoggedIn();
		return;
	}

	// If here is no account in the database, launch the first connection wizard
	// TODO only if can create password

	bool firstConnection {};
	{
		auto transaction {getDbSession().createSharedTransaction()};
		firstConnection = Database::User::getCount(getDbSession()) == 0;
	}

	LMS_LOG(UI, DEBUG) << "Creating root widget. First connection = " << firstConnection;

	if (firstConnection && Service<::Auth::IPasswordService>::get()->canSetPasswords())
	{
		setTheme();
		root()->addWidget(std::make_unique<InitWizardView>());
	}
	else
	{
		Auth* auth {root()->addNew<Auth>()};
		auth->userLoggedIn.connect(this, [this](Database::IdType userId)
		{
			_userId = userId;
			_userAuthStrong = true;
			onUserLoggedIn();
		});
	}
}

void
LmsApplication::setTheme()
{
	Database::User::UITheme theme {Database::User::defaultUITheme};
	{
		auto transaction {getDbSession().createSharedTransaction()};
		if (const auto user {getUser()})
			theme = user->getUITheme();
	}

	WApplication::setTheme(std::make_unique<LmsTheme>(theme));
}

void
LmsApplication::finalize()
{
	if (_userId)
	{
		LmsApplicationInfo info = LmsApplicationInfo::fromEnvironment(environment());

		getApplicationGroup().postOthers([info]
		{
			LmsApp->getEvents().appClosed(info);
		});

		getApplicationGroup().leave();
	}

	preQuit().emit();
}

Wt::WLink
LmsApplication::createArtistLink(Database::Artist::pointer artist)
{
	return Wt::WLink {Wt::LinkType::InternalPath, "/artist/" + std::to_string(artist.id())};
}

std::unique_ptr<Wt::WAnchor>
LmsApplication::createArtistAnchor(Database::Artist::pointer artist, bool addText)
{
	auto res = std::make_unique<Wt::WAnchor>(createArtistLink(artist));

	if (addText)
	{
		res->setTextFormat(Wt::TextFormat::Plain);
		res->setText(Wt::WString::fromUTF8(artist->getName()));
		res->setToolTip(Wt::WString::fromUTF8(artist->getName()), Wt::TextFormat::Plain);
	}

	return res;
}

Wt::WLink
LmsApplication::createReleaseLink(Database::Release::pointer release)
{
	return Wt::WLink {Wt::LinkType::InternalPath, "/release/" + std::to_string(release.id())};
}

std::unique_ptr<Wt::WAnchor>
LmsApplication::createReleaseAnchor(Database::Release::pointer release, bool addText)
{
	auto res = std::make_unique<Wt::WAnchor>(createReleaseLink(release));

	if (addText)
	{
		res->setWordWrap(false);
		res->setTextFormat(Wt::TextFormat::Plain);
		res->setText(Wt::WString::fromUTF8(release->getName()));
		res->setToolTip(Wt::WString::fromUTF8(release->getName()), Wt::TextFormat::Plain);
	}

	return res;
}

std::unique_ptr<Wt::WText>
LmsApplication::createCluster(Database::Cluster::pointer cluster, bool canDelete)
{
	auto getStyleClass = [](const Database::Cluster::pointer cluster)
	{
		switch (cluster->getType().id() % 6)
		{
			case 0: return "label-info";
			case 1: return "label-warning";
			case 2: return "label-primary";
			case 3: return "label-default";
			case 4: return "label-success";
			case 5: return "label-danger";
		}
		return "label-default";
	};

	const std::string styleClass {getStyleClass(cluster)};
	auto res {std::make_unique<Wt::WText>(std::string {} + (canDelete ? "<i class=\"fa fa-times-circle\"></i> " : "") + Wt::WString::fromUTF8(cluster->getName()), Wt::TextFormat::UnsafeXHTML)};

	res->setStyleClass("Lms-cluster label " + styleClass);
	res->setToolTip(cluster->getType()->getName(), Wt::TextFormat::Plain);
	res->setInline(true);

	return res;
}

Wt::WPopupMenu*
LmsApplication::createPopupMenu()
{
	_popupMenu = std::make_unique<Wt::WPopupMenu>();
	return _popupMenu.get();
}

void
LmsApplication::handleException(LmsApplicationException& e)
{
	root()->clear();
	Wt::WTemplate* t {root()->addNew<Wt::WTemplate>(Wt::WString::tr("Lms.Error.template"))};
	t->addFunction("tr", &Wt::WTemplate::Functions::tr);

	t->bindString("error", e.what(), Wt::TextFormat::Plain);
	Wt::WPushButton* btn {t->bindNew<Wt::WPushButton>("btn-go-home", Wt::WString::tr("Lms.Error.go-home"))};
	btn->clicked().connect([this]()
	{
		redirect(defaultPath);
	});
}

void
LmsApplication::goHomeAndQuit()
{
	WApplication::quit("");
	redirect(".");
}

enum IdxRoot
{
	IdxExplore	= 0,
	IdxPlayQueue,
	IdxSettings,
	IdxAdminDatabase,
	IdxAdminUsers,
	IdxAdminUser,
};

static
void
handlePathChange(Wt::WStackedWidget& stack, bool isAdmin)
{
	static const struct
	{
		std::string path;
		int index;
		bool admin;
	} views[] =
	{
		{ "/artists",		IdxExplore,		false },
		{ "/artist",		IdxExplore,		false },
		{ "/releases",		IdxExplore,		false },
		{ "/release",		IdxExplore,		false },
		{ "/search",		IdxExplore,		false },
		{ "/tracks",		IdxExplore,		false },
		{ "/playqueue",		IdxPlayQueue,		false },
		{ "/settings",		IdxSettings,		false },
		{ "/admin/database",	IdxAdminDatabase,	true },
		{ "/admin/users",	IdxAdminUsers,		true },
		{ "/admin/user",	IdxAdminUser,		true },
	};

	LMS_LOG(UI, DEBUG) << "Internal path changed to '" << wApp->internalPath() << "'";

	LmsApp->doJavaScript(R"($('.navbar-nav li.active').removeClass('active'); $('.navbar-nav a[href="' + location.pathname + '"]').closest('li').addClass('active');)");

	for (const auto& view : views)
	{
		if (wApp->internalPathMatches(view.path))
		{
			if (view.admin && !isAdmin)
				break;

			stack.setCurrentIndex(view.index);
			return;
		}
	}

	wApp->setInternalPath(defaultPath, true);
}

LmsApplicationGroup&
LmsApplication::getApplicationGroup()
{
	return _appGroups.get(*_userId);
}

void
LmsApplication::logoutUser()
{
	{
		auto transaction {getDbSession().createUniqueTransaction()};
		getUser().modify()->clearAuthTokens();
	}

	LMS_LOG(UI, INFO) << "User '" << getUserLoginName() << " 'logged out";
	goHomeAndQuit();
}

void
LmsApplication::onUserLoggedIn()
{
	setTheme();
	root()->clear();

	const LmsApplicationInfo info {LmsApplicationInfo::fromEnvironment(environment())};

	LMS_LOG(UI, INFO) << "User '" << getUserLoginName() << "' logged in from '" << environment().clientAddress() << "', user agent = " << environment().userAgent();
	getApplicationGroup().join(info);

	getApplicationGroup().postOthers([info]
	{
		LmsApp->getEvents().appOpen(info);
	});

	createHome();
}

void
LmsApplication::createHome()
{
	_coverResource = std::make_shared<CoverResource>();

	declareJavaScriptFunction("onLoadCover", "function(id) { id.className += \" Lms-cover-loaded\"}");
	doJavaScript("$('body').tooltip({ selector: '[data-toggle=\"tooltip\"]'})");

	Wt::WTemplate* main {root()->addWidget(std::make_unique<Wt::WTemplate>(Wt::WString::tr("Lms.template")))};

	main->addFunction("tr", &Wt::WTemplate::Functions::tr);

	// MediaPlayer
	_mediaPlayer = main->bindNew<MediaPlayer>("player");

	main->bindNew<Wt::WAnchor>("title",  Wt::WLink {Wt::LinkType::InternalPath, defaultPath}, "LMS");
	main->bindNew<Wt::WAnchor>("artists", Wt::WLink {Wt::LinkType::InternalPath, "/artists"}, Wt::WString::tr("Lms.Explore.artists"));
	main->bindNew<Wt::WAnchor>("releases", Wt::WLink {Wt::LinkType::InternalPath, "/releases"}, Wt::WString::tr("Lms.Explore.releases"));
	main->bindNew<Wt::WAnchor>("tracks", Wt::WLink {Wt::LinkType::InternalPath, "/tracks"}, Wt::WString::tr("Lms.Explore.tracks"));

	Filters* filters {main->bindNew<Filters>("filters")};
	main->bindNew<Wt::WAnchor>("playqueue", Wt::WLink {Wt::LinkType::InternalPath, "/playqueue"}, Wt::WString::tr("Lms.PlayQueue.playqueue"));
	main->bindString("username", getUserLoginName(), Wt::TextFormat::Plain);
	main->bindNew<Wt::WAnchor>("settings", Wt::WLink {Wt::LinkType::InternalPath, "/settings"}, Wt::WString::tr("Lms.Settings.menu-settings"));

	{
		Wt::WAnchor* logout {main->bindNew<Wt::WAnchor>("logout")};
		logout->setText(Wt::WString::tr("Lms.logout"));
		logout->clicked().connect(this, &LmsApplication::logoutUser);
	}

	Wt::WLineEdit* searchEdit {main->bindNew<Wt::WLineEdit>("search")};
	searchEdit->setPlaceholderText(Wt::WString::tr("Lms.Explore.Search.search-placeholder"));

	if (isUserAdmin())
	{
		main->setCondition("if-is-admin", true);
		main->bindNew<Wt::WAnchor>("database", Wt::WLink {Wt::LinkType::InternalPath, "/admin/database"}, Wt::WString::tr("Lms.Admin.Database.menu-database"));
		main->bindNew<Wt::WAnchor>("users", Wt::WLink {Wt::LinkType::InternalPath, "/admin/users"}, Wt::WString::tr("Lms.Admin.Users.menu-users"));
	}

	// Contents
	// Order is important in mainStack, see IdxRoot!
	Wt::WStackedWidget* mainStack {main->bindNew<Wt::WStackedWidget>("contents")};
	mainStack->setAttributeValue("style", "overflow-x:visible;overflow-y:visible;");

	Explore* explore {mainStack->addNew<Explore>(filters)};
	_playQueue = mainStack->addNew<PlayQueue>();
	mainStack->addNew<SettingsView>();

	searchEdit->enterPressed().connect([=]
	{
		setInternalPath("/search", true);
	});

	searchEdit->textInput().connect([=]
	{
		setInternalPath("/search", true);
		explore->search(searchEdit->text());
	});

	// Admin stuff
	if (isUserAdmin())
	{
		mainStack->addNew<DatabaseSettingsView>();
		mainStack->addNew<UsersView>();
		mainStack->addNew<UserView>();
	}

	explore->tracksAction.connect([this] (PlayQueueAction action, const std::vector<Database::IdType>& trackIds)
	{
		_playQueue->processTracks(action, trackIds);
	});

	// Events from MediaPlayer
	_mediaPlayer->playNext.connect([this]
	{
		_playQueue->playNext();
	});
	_mediaPlayer->playPrevious.connect([this]
	{
		_playQueue->playPrevious();
	});
	_mediaPlayer->playbackEnded.connect([this]
	{
		_playQueue->playNext();
	});

	_playQueue->trackSelected.connect([this] (Database::IdType trackId, bool play, float replayGain)
	{
		_mediaPlayer->loadTrack(trackId, play, replayGain);
	});

	_playQueue->trackUnselected.connect([this]
	{
		_mediaPlayer->stop();
	});

	if (isUserAdmin())
	{
		_scannerEvents.scanComplete.connect([=] (const Scanner::ScanStats& stats)
		{
			notifyMsg(MsgType::Info, Wt::WString::tr("Lms.Admin.Database.scan-complete")
				.arg(static_cast<unsigned>(stats.nbFiles()))
				.arg(static_cast<unsigned>(stats.additions))
				.arg(static_cast<unsigned>(stats.updates))
				.arg(static_cast<unsigned>(stats.deletions))
				.arg(static_cast<unsigned>(stats.duplicates.size()))
				.arg(static_cast<unsigned>(stats.errors.size())));
		});
	}

	// Events from Application group
	_events.appOpen.connect([=]
	{
		// Only one active session by user
		if (!LmsApp->isUserDemo())
		{
			quit(Wt::WString::tr("Lms.quit-other-session"));
		}
	});

	internalPathChanged().connect([=]
	{
		handlePathChange(*mainStack, isUserAdmin());
	});

	handlePathChange(*mainStack, isUserAdmin());
}

void
LmsApplication::notify(const Wt::WEvent& event)
{
	try
	{
		WApplication::notify(event);
	}
	catch (LmsApplicationException& e)
	{
		LMS_LOG(UI, WARNING) << "Caught a LmsApplication exception: " << e.what();
		handleException(e);
	}
	catch (std::exception& e)
	{
		LMS_LOG(UI, ERROR) << "Caught exception: " << e.what();
		throw LmsException {"Internal error"}; // Do not put details here at it may appear on the user rendered html
	}
}

static std::string msgTypeToString(LmsApplication::MsgType type)
{
	switch(type)
	{
		case LmsApplication::MsgType::Success:	return "success";
		case LmsApplication::MsgType::Info:	return "info";
		case LmsApplication::MsgType::Warning:	return "warning";
		case LmsApplication::MsgType::Danger:	return "danger";
	}
	return "";
}

void
LmsApplication::post(std::function<void()> func)
{
	Wt::WServer::instance()->post(LmsApp->sessionId(), std::move(func));
}


void
LmsApplication::notifyMsg(MsgType type, const Wt::WString& message, std::chrono::milliseconds duration)
{
	LMS_LOG(UI, INFO) << "Notifying message '" << message.toUTF8() << "' of type '" << msgTypeToString(type) << "'";

	std::ostringstream oss;

	oss << "$.notify({"
			"message: '" << StringUtils::jsEscape(message.toUTF8()) << "'"
		"},{"
			"type: '" << msgTypeToString(type) << "',"
			"placement: {from: 'bottom', align: 'right'},"
			"timer: 250,"
			"offset: {x: 20, y: 80},"
			"delay: " << duration.count() << ""
		"});";

	LmsApp->doJavaScript(oss.str());
}


} // namespace UserInterface


