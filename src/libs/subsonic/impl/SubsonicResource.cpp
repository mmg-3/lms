/*
 * copyright (c) 2019 emeric poupon
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
#include "subsonic/SubsonicResource.hpp"

#include <atomic>
#include <ctime>
#include <iomanip>
#include <unordered_map>

#include <Wt/WLocalDateTime.h>

#include "auth/IPasswordService.hpp"
#include "cover/ICoverArtGrabber.hpp"
#include "database/Artist.hpp"
#include "database/Cluster.hpp"
#include "database/Db.hpp"
#include "database/Release.hpp"
#include "database/Session.hpp"
#include "database/Track.hpp"
#include "database/TrackBookmark.hpp"
#include "database/TrackList.hpp"
#include "database/User.hpp"
#include "recommendation/IEngine.hpp"
#include "utils/Logger.hpp"
#include "utils/Random.hpp"
#include "utils/Service.hpp"
#include "utils/String.hpp"
#include "utils/Utils.hpp"
#include "ParameterParsing.hpp"
#include "RequestContext.hpp"
#include "Scan.hpp"
#include "Stream.hpp"
#include "SubsonicResponse.hpp"

using namespace Database;

static const std::string	genreClusterName {"GENRE"};
static const std::string	reportedStarredDate {"2000-01-01T00:00:00"};
static const std::string	reportedDummyDate {"2000-01-01T00:00:00"};
static const unsigned long long	reportedDummyDateULong {946684800000ULL}; // 2000-01-01T00:00:00 UTC

namespace API::Subsonic
{
	struct ClientVersion
	{
		unsigned major {};
		unsigned minor {};
		unsigned patch {};
	};
}

namespace StringUtils
{
	template<>
	std::optional<API::Subsonic::ClientVersion>
	readAs(const std::string& str)
	{
		// Expects "X.Y.Z"
		const auto numbers {StringUtils::splitString(str, ".")};
		if (numbers.size() < 2 || numbers.size() > 3)
			return std::nullopt;

		API::Subsonic::ClientVersion version;

		auto number {StringUtils::readAs<unsigned>(numbers[0])};
		if (!number)
			return std::nullopt;
		version.major = *number;

		number = {StringUtils::readAs<unsigned>(numbers[1])};
		if (!number)
			return std::nullopt;
		version.minor = *number;

		if (numbers.size() == 3)
		{
			number = {StringUtils::readAs<unsigned>(numbers[2])};
			if (!number)
				return std::nullopt;
			version.patch = *number;
		}

		return version;
	}

}


namespace API::Subsonic
{

static
void
checkSetPasswordImplemented()
{
	Auth::IPasswordService* passwordService {Service<Auth::IPasswordService>::get()};
	if (!passwordService || !passwordService->canSetPasswords())
		throw NotImplementedGenericError {};
}

static
std::string
makeNameFilesystemCompatible(const std::string& name)
{
	return StringUtils::replaceInString(name, "/", "_");
}

static
std::string
decodePasswordIfNeeded(const std::string& password)
{
	if (password.find("enc:") == 0)
	{
		auto decodedPassword {StringUtils::stringFromHex(password.substr(4))};
		if (!decodedPassword)
			return password; // fallback on plain password

		return *decodedPassword;
	}

	return password;
}

struct ClientInfo
{
	std::string name;
	std::string user;
	std::string password;
	ClientVersion version;
};

static
ClientInfo
getClientInfo(const Wt::Http::ParameterMap& parameters)
{
	ClientInfo res;

	// Mandatory parameters
	res.name = getMandatoryParameterAs<std::string>(parameters, "c");
	res.version = getMandatoryParameterAs<ClientVersion>(parameters, "v");
	if (res.version.major > API_VERSION_MAJOR)
		throw ServerMustUpgradeError {};
	if (res.version.major < API_VERSION_MAJOR)
		throw ClientMustUpgradeError {};
	if (res.version.minor > Response::getAPIMinorVersion(res.name))
		throw ServerMustUpgradeError {};

	res.user = getMandatoryParameterAs<std::string>(parameters, "u");
	res.password = decodePasswordIfNeeded(getMandatoryParameterAs<std::string>(parameters, "p"));

	return res;
}

SubsonicResource::SubsonicResource(Db& db)
: _db {db}
{
}

static
std::string parameterMapToDebugString(const Wt::Http::ParameterMap& parameterMap)
{
	auto censorValue = [](const std::string& type, const std::string& value) -> std::string
	{
		if (type == "p" || type == "password")
			return "*SENSIBLE DATA*";
		else
			return value;
	};

	std::string res;

	for (const auto& params : parameterMap)
	{
		res += "{" + params.first + "=";
		if (params.second.size() == 1)
		{
			res += censorValue(params.first, params.second.front());
		}
		else
		{
			res += "{";
			for (const std::string& param : params.second)
				res += censorValue(params.first, param) + ",";
			res += "}";
		}
		res += "}, ";
	}

	return res;
}

static
void
checkUserIsMySelfOrAdmin(RequestContext& context, const std::string& username)
{
	if (username != context.userName)
	{
		User::pointer currentUser {User::getByLoginName(context.dbSession, context.userName)};
		if (!currentUser)
			throw RequestedDataNotFoundError {};

		if (!currentUser->isAdmin())
			throw UserNotAuthorizedError {};
	}
}

static
std::string
getArtistNames(const std::vector<Artist::pointer>& artists)
{
	if (artists.size() == 1)
		return artists.front()->getName();

	std::vector<std::string> names;
	names.resize(artists.size());

	std::transform(std::cbegin(artists), std::cend(artists), std::begin(names),
			[](const Artist::pointer& artist)
			{
				return artist->getName();
			});

	return StringUtils::joinStrings(names, ", ");
}

static
std::string
getTrackPath(const Track::pointer& track)
{
	std::string path;

	// The track path has to be relative from the root

	const auto release {track->getRelease()};
	if (release)
	{
		auto artists {release->getReleaseArtists()};
		if (artists.empty())
			artists = release->getArtists();

		if (artists.size() > 1)
			path = "Various Artists/";
		else if (artists.size() == 1)
			path = makeNameFilesystemCompatible(artists.front()->getName()) + "/";

		path += makeNameFilesystemCompatible(track->getRelease()->getName()) + "/";
	}

	if (track->getDiscNumber())
		path += std::to_string(*track->getDiscNumber()) + "-";
	if (track->getTrackNumber())
		path += std::to_string(*track->getTrackNumber()) + "-";

	path += makeNameFilesystemCompatible(track->getName());

	if (track->getPath().has_extension())
		path += track->getPath().extension();

	return path;
}

static
std::string_view
formatToSuffix(AudioFormat format)
{
	switch (format)
	{
		case AudioFormat::MP3:			return "mp3";
		case AudioFormat::OGG_OPUS:		return "opus";
		case AudioFormat::MATROSKA_OPUS:	return "mka";
		case AudioFormat::OGG_VORBIS:		return "ogg";
		case AudioFormat::WEBM_VORBIS:		return "webm";
	}

	return "";
}

static
Response::Node
trackToResponseNode(const Track::pointer& track, Session& dbSession, const User::pointer& user)
{
	Response::Node trackResponse;

	trackResponse.setAttribute("id", IdToString({Id::Type::Track, track.id()}));
	trackResponse.setAttribute("isDir", false);
	trackResponse.setAttribute("title", track->getName());
	if (track->getTrackNumber())
		trackResponse.setAttribute("track", *track->getTrackNumber());
	if (track->getDiscNumber())
		trackResponse.setAttribute("discNumber", *track->getDiscNumber());
	if (track->getYear())
		trackResponse.setAttribute("year", *track->getYear());

	trackResponse.setAttribute("path", getTrackPath(track));
	{
		std::error_code ec;
		const auto fileSize {std::filesystem::file_size(track->getPath(), ec)};
		if (!ec)
			trackResponse.setAttribute("size", fileSize);
	}

	if (track->getPath().has_extension())
	{
		auto extension {track->getPath().extension()};
		trackResponse.setAttribute("suffix", extension.string().substr(1));
	}

	if (user->getSubsonicTranscodeEnable())
		trackResponse.setAttribute("transcodedSuffix", formatToSuffix(user->getSubsonicTranscodeFormat()));

	trackResponse.setAttribute("coverArt", IdToString({Id::Type::Track, track.id()}));

	const std::vector<Artist::pointer>& artists {track->getArtists({TrackArtistLinkType::Artist})};
	LMS_LOG(API_SUBSONIC, DEBUG) << "Artists count = " << artists.size();
	if (!artists.empty())
	{
		trackResponse.setAttribute("artist", getArtistNames(artists));

		if (artists.size() == 1)
			trackResponse.setAttribute("artistId", IdToString({Id::Type::Artist, artists.front().id()}));
	}

	if (track->getRelease())
	{
		trackResponse.setAttribute("album", track->getRelease()->getName());
		trackResponse.setAttribute("albumId", IdToString({Id::Type::Release, track->getRelease().id()}));
		trackResponse.setAttribute("parent", IdToString({Id::Type::Release, track->getRelease().id()}));
	}

	trackResponse.setAttribute("duration", std::chrono::duration_cast<std::chrono::seconds>(track->getDuration()).count());
	trackResponse.setAttribute("type", "music");

	if (user->hasStarredTrack(track))
		trackResponse.setAttribute("starred", reportedStarredDate);

	// Report the first GENRE for this track
	ClusterType::pointer clusterType {ClusterType::getByName(dbSession, genreClusterName)};
	if (clusterType)
	{
		auto clusters {track->getClusterGroups({clusterType}, 1)};
		if (!clusters.empty() && !clusters.front().empty())
			trackResponse.setAttribute("genre", clusters.front().front()->getName());
	}

	return trackResponse;
}

static
Response::Node
trackBookmarkToResponseNode(const TrackBookmark::pointer& trackBookmark)
{
	Response::Node trackBookmarkNode;

	trackBookmarkNode.setAttribute("position", trackBookmark->getOffset().count());
	if (!trackBookmark->getComment().empty())
		trackBookmarkNode.setAttribute("comment", trackBookmark->getComment());
	trackBookmarkNode.setAttribute("created", reportedDummyDate);
	trackBookmarkNode.setAttribute("changed", reportedDummyDate);
	trackBookmarkNode.setAttribute("username", trackBookmark->getUser()->getLoginName());

	return trackBookmarkNode;
}

static
Response::Node
releaseToResponseNode(const Release::pointer& release, Session& dbSession, const User::pointer& user, bool id3)
{
	Response::Node albumNode;

	if (id3)
	{
		albumNode.setAttribute("name", release->getName());
		albumNode.setAttribute("songCount", release->getTracksCount());
		albumNode.setAttribute("duration", std::chrono::duration_cast<std::chrono::seconds>(release->getDuration()).count());
	}
	else
	{
		albumNode.setAttribute("title", release->getName());
		albumNode.setAttribute("isDir", true);
	}

	{
		std::time_t t {release->getLastWritten().toTime_t()};
		std::tm gmTime;
		std::ostringstream oss; oss << std::put_time(::gmtime_r(&t, &gmTime), "%FT%T");
		albumNode.setAttribute("created", oss.str());
	}

	albumNode.setAttribute("id", IdToString({Id::Type::Release, release.id()}));
	albumNode.setAttribute("coverArt", IdToString({Id::Type::Release, release.id()}));
	auto releaseYear {release->getReleaseYear()};
	if (releaseYear)
		albumNode.setAttribute("year", *releaseYear);

	auto artists {release->getReleaseArtists()};
	if (artists.empty())
		artists = release->getArtists();

	if (artists.empty() && !id3)
	{
		albumNode.setAttribute("parent", IdToString({Id::Type::Root}));
	}
	else if (!artists.empty())
	{
		albumNode.setAttribute("artist", getArtistNames(artists));

		if (artists.size() == 1)
		{
			if (id3)
				albumNode.setAttribute("artistId", IdToString({Id::Type::Artist, artists.front().id()}));
			else
				albumNode.setAttribute("parent", IdToString({Id::Type::Artist, artists.front().id()}));
		}
		else
		{
			if (!id3)
				albumNode.setAttribute("parent", IdToString({Id::Type::Root}));
		}
	}

	if (id3)
	{
		// Report the first GENRE for this track
		ClusterType::pointer clusterType {ClusterType::getByName(dbSession, genreClusterName)};
		if (clusterType)
		{
			auto clusters {release->getClusterGroups({clusterType}, 1)};
			if (!clusters.empty() && !clusters.front().empty())
				albumNode.setAttribute("genre", clusters.front().front()->getName());
		}
	}

	if (user->hasStarredRelease(release))
		albumNode.setAttribute("starred", reportedStarredDate);

	return albumNode;
}

static
Response::Node
artistToResponseNode(const User::pointer& user, const Artist::pointer& artist, bool id3)
{
	Response::Node artistNode;

	artistNode.setAttribute("id", IdToString({Id::Type::Artist, artist.id()}));
	artistNode.setAttribute("name", artist->getName());

	if (id3)
		artistNode.setAttribute("albumCount", artist->getReleaseCount());

	if (user->hasStarredArtist(artist))
		artistNode.setAttribute("starred", reportedStarredDate);

	return artistNode;
}

static
Response::Node
clusterToResponseNode(const Cluster::pointer& cluster)
{
	Response::Node clusterNode;

	clusterNode.setValue(cluster->getName());
	clusterNode.setAttribute("songCount", cluster->getTracksCount());
	clusterNode.setAttribute("albumCount", cluster->getReleasesCount());

	return clusterNode;
}

static
Response::Node
userToResponseNode(const User::pointer& user)
{
	Response::Node userNode;

	userNode.setAttribute("username", user->getLoginName());
	userNode.setAttribute("scrobblingEnabled", true);
	userNode.setAttribute("adminRole", user->isAdmin());
	userNode.setAttribute("settingsRole", true);
	userNode.setAttribute("downloadRole", true);
	userNode.setAttribute("uploadRole", false);
	userNode.setAttribute("playlistRole", true);
	userNode.setAttribute("coverArtRole", false);
	userNode.setAttribute("commentRole", false);
	userNode.setAttribute("podcastRole", false);
	userNode.setAttribute("streamRole", true);
	userNode.setAttribute("jukeboxRole", false);
	userNode.setAttribute("shareRole", false);

	Response::Node folder;
	folder.setValue("0");
	userNode.addArrayChild("folder", std::move(folder));

	return userNode;
}

static
Response
handlePingRequest(RequestContext& context)
{
	return Response::createOkResponse(context);
}

static
Response
handleChangePassword(RequestContext& context)
{
	std::string username {getMandatoryParameterAs<std::string>(context.parameters, "username")};
	std::string password {decodePasswordIfNeeded(getMandatoryParameterAs<std::string>(context.parameters, "password"))};

	try
	{
		auto transaction {context.dbSession.createUniqueTransaction()};

		checkUserIsMySelfOrAdmin(context, username);

		User::pointer user {User::getByLoginName(context.dbSession, username)};
		if (!user)
			throw UserNotAuthorizedError {};

		Service<Auth::IPasswordService>::get()->setPassword(user, password);
	}
	catch (Auth::IPasswordService::PasswordTooWeakException&)
	{
		throw PasswordTooWeakGenericError {};
	}
	catch (Auth::Exception& authException)
	{
		throw UserNotAuthorizedError {};
	}

	return Response::createOkResponse(context);
}

static
Response
handleCreatePlaylistRequest(RequestContext& context)
{
	// Optional params
	auto id {getParameterAs<Id>(context.parameters, "playlistId")};
	if (id && id->type != Id::Type::Playlist)
		throw BadParameterGenericError {"playlistId"};

	auto name {getParameterAs<std::string>(context.parameters, "name")};

	std::vector<Id> trackIds {getMultiParametersAs<Id>(context.parameters, "songId")};
	if (!std::all_of(std::cbegin(trackIds), std::cend(trackIds ), [](const Id& id) { return id.type == Id::Type::Track; }))
		throw BadParameterGenericError {"songId"};

	if (!name && !id)
		throw RequiredParameterMissingError {"name or id"};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	TrackList::pointer tracklist;
	if (id)
	{
		tracklist = TrackList::getById(context.dbSession, id->value);
		if (!tracklist
			|| tracklist->getUser() != user
			|| tracklist->getType() != TrackList::Type::Playlist)
		{
			throw RequestedDataNotFoundError {};
		}

		if (name)
			tracklist.modify()->setName(*name);
	}
	else
	{
		tracklist = TrackList::create(context.dbSession, *name, TrackList::Type::Playlist, false, user);
	}

	for (const Id& trackId : trackIds)
	{
		Track::pointer track {Track::getById(context.dbSession, trackId.value)};
		if (!track)
			continue;

		TrackListEntry::create(context.dbSession, track, tracklist );
	}

	return Response::createOkResponse(context);
}

static
Response
handleCreateUserRequest(RequestContext& context)
{
	std::string username {getMandatoryParameterAs<std::string>(context.parameters, "username")};
	std::string password {decodePasswordIfNeeded(getMandatoryParameterAs<std::string>(context.parameters, "password"))};
	// Just ignore all the other fields as we don't handle them

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, username)};
	if (user)
		throw UserAlreadyExistsGenericError {};

	user = User::create(context.dbSession, username);

	try
	{
		Service<Auth::IPasswordService>::get()->setPassword(user, password);
	}
	catch (const Auth::IPasswordService::PasswordTooWeakException&)
	{
		user.remove();
		throw PasswordTooWeakGenericError {};
	}
	catch (const Auth::Exception& exception)
	{
		user.remove();
		throw UserNotAuthorizedError {};
	}

	return Response::createOkResponse(context);
}

static
Response
handleDeletePlaylistRequest(RequestContext& context)
{
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (id.type != Id::Type::Playlist)
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	TrackList::pointer tracklist {TrackList::getById(context.dbSession, id.value)};
	if (!tracklist
		|| tracklist->getUser() != user
		|| tracklist->getType() != TrackList::Type::Playlist)
	{
		throw RequestedDataNotFoundError {};
	}

	tracklist.remove();

	return Response::createOkResponse(context);
}

static
Response
handleDeleteUserRequest(RequestContext& context)
{
	std::string username {getMandatoryParameterAs<std::string>(context.parameters, "username")};

	// cannot delete ourself
	if (username == context.userName)
		throw UserNotAuthorizedError {};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, username)};
	if (!user)
		throw RequestedDataNotFoundError {};

	user.remove();

	return Response::createOkResponse(context);
}

static
Response
handleGetLicenseRequest(RequestContext& context)
{
	Response response {Response::createOkResponse(context)};

	Response::Node& licenseNode {response.createNode("license")};
	licenseNode.setAttribute("licenseExpires", "2025-09-03T14:46:43");
	licenseNode.setAttribute("email", "foo@bar.com");
	licenseNode.setAttribute("valid", true);

	return response;
}

static
Response
handleGetRandomSongsRequest(RequestContext& context)
{
	// Optional params
	std::size_t size {getParameterAs<std::size_t>(context.parameters, "size").value_or(50)};
	size = std::min(size, std::size_t {500});

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	auto tracks {Track::getAllRandom(context.dbSession, {}, size)};

	Response response {Response::createOkResponse(context)};

	Response::Node& randomSongsNode {response.createNode("randomSongs")};
	for (const Track::pointer& track : tracks)
		randomSongsNode.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));

	return response;
}

static
Response
handleGetAlbumListRequestCommon(const RequestContext& context, bool id3)
{
	// Mandatory params
	const std::string type {getMandatoryParameterAs<std::string>(context.parameters, "type")};

	// Optional params
	const std::size_t size {getParameterAs<std::size_t>(context.parameters, "size").value_or(10)};
	const std::size_t offset {getParameterAs<std::size_t>(context.parameters, "offset").value_or(0)};

	const Range range {offset, size};

	std::vector<Release::pointer> releases;

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	if (type == "alphabeticalByName")
	{
		releases = Release::getAll(context.dbSession, range);
	}
	else if (type == "alphabeticalByArtist")
	{
		releases = Release::getAllOrderedByArtist(context.dbSession, offset, size);
	}
	else if (type == "byGenre")
	{
		// Mandatory param
		std::string genre {getMandatoryParameterAs<std::string>(context.parameters, "genre")};

		ClusterType::pointer clusterType {ClusterType::getByName(context.dbSession, genreClusterName)};
		if (clusterType)
		{
			Cluster::pointer cluster {clusterType->getCluster(genre)};
			if (cluster)
			{
				bool more;
				releases = Release::getByFilter(context.dbSession, {cluster.id()}, {}, range, more);
			}
		}
	}
	else if (type == "byYear")
	{
		int fromYear {getMandatoryParameterAs<int>(context.parameters, "fromYear")};
		int toYear {getMandatoryParameterAs<int>(context.parameters, "toYear")};

		releases = Release::getByYear(context.dbSession, fromYear, toYear, range);
	}
	else if (type == "frequent")
	{
		bool moreResults {};
		releases = user->getPlayedTrackList(context.dbSession)->getTopReleases({}, range, moreResults);
	}
	else if (type == "newest")
	{
		bool moreResults {};
		releases = Release::getLastWritten(context.dbSession, std::nullopt, {}, range, moreResults);
	}
	else if (type == "random")
	{
		// Random results are paginated, but there is no acceptable way to handle the pagination params without repeating some albums
		releases = Release::getAllRandom(context.dbSession, {}, size);
	}
	else if (type == "recent")
	{
		bool moreResults {};
		releases = user->getPlayedTrackList(context.dbSession)->getReleasesReverse({}, range, moreResults);
	}
	else if (type == "starred")
	{
		bool moreResults {};
		releases = Release::getStarred(context.dbSession, user, {}, range, moreResults);
	}
	else
		throw NotImplementedGenericError {};

	Response response {Response::createOkResponse(context)};
	Response::Node& albumListNode {response.createNode(id3 ? "albumList2" : "albumList")};

	for (const Release::pointer& release : releases)
		albumListNode.addArrayChild("album", releaseToResponseNode(release, context.dbSession, user, id3));

	return response;
}

static
Response
handleGetAlbumListRequest(RequestContext& context)
{
	return handleGetAlbumListRequestCommon(context, false /* no id3 */);
}

static
Response
handleGetAlbumList2Request(RequestContext& context)
{
	return handleGetAlbumListRequestCommon(context, true /* id3 */);
}

static
Response
handleGetAlbumRequest(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};

	if (id.type != Id::Type::Release)
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createSharedTransaction()};

	Release::pointer release {Release::getById(context.dbSession, id.value)};
	if (!release)
		throw RequestedDataNotFoundError {};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node releaseNode {releaseToResponseNode(release, context.dbSession, user, true /* id3 */)};

	auto tracks {release->getTracks()};
	for (const Track::pointer& track : tracks)
		releaseNode.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));

	response.addNode("album", std::move(releaseNode));

	return response;
}

static
Response
handleGetArtistRequest(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};

	if (id.type != Id::Type::Artist)
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createSharedTransaction()};

	Artist::pointer artist {Artist::getById(context.dbSession, id.value)};
	if (!artist)
		throw RequestedDataNotFoundError {};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node artistNode {artistToResponseNode(user, artist, true /* id3 */)};

	auto releases {artist->getReleases()};
	for (const Release::pointer& release : releases)
		artistNode.addArrayChild("album", releaseToResponseNode(release, context.dbSession, user, true /* id3 */));

	response.addNode("artist", std::move(artistNode));

	return response;
}

static
Response
handleGetArtistInfoRequestCommon(RequestContext& context, bool id3)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (id.type != Id::Type::Artist)
		throw BadParameterGenericError {"id"};

	// Optional params
	std::size_t count {getParameterAs<std::size_t>(context.parameters, "count").value_or(20)};

	Response response {Response::createOkResponse(context)};
	Response::Node& artistInfoNode {response.createNode(id3 ? "artistInfo2" : "artistInfo")};

	{
		auto transaction {context.dbSession.createSharedTransaction()};

		Artist::pointer artist {Artist::getById(context.dbSession, id.value)};
		if (!artist)
			throw RequestedDataNotFoundError {};

		std::optional<UUID> artistMBID {artist->getMBID()};
		if (artistMBID)
			artistInfoNode.createChild("musicBrainzId").setValue(artistMBID->getAsString());
	}

	auto similarArtistsId {Service<Recommendation::IEngine>::get()->getSimilarArtists(context.dbSession,
			id.value,
			{TrackArtistLinkType::Artist, TrackArtistLinkType::ReleaseArtist},
			count)};

	{
		auto transaction {context.dbSession.createSharedTransaction()};

		User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
		if (!user)
			throw UserNotAuthorizedError {};

		for ( const auto& similarArtistId : similarArtistsId )
		{
			Artist::pointer similarArtist {Artist::getById(context.dbSession, similarArtistId)};
			if (similarArtist)
				artistInfoNode.addArrayChild("similarArtist", artistToResponseNode(user, similarArtist, id3));
		}
	}

	return response;
}

static
Response
handleGetArtistInfoRequest(RequestContext& context)
{
	return handleGetArtistInfoRequestCommon(context, false /* no id3 */);
}

static
Response
handleGetArtistInfo2Request(RequestContext& context)
{
	return handleGetArtistInfoRequestCommon(context, true /* id3 */);
}

static
Response
handleGetArtistsRequest(RequestContext& context)
{
	Response response {Response::createOkResponse(context)};

	Response::Node& artistsNode {response.createNode("artists")};
	artistsNode.setAttribute("ignoredArticles", "");
	artistsNode.setAttribute("lastModified", reportedDummyDateULong);

	Response::Node& indexNode {artistsNode.createArrayChild("index")};
	indexNode.setAttribute("name", "?");

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	std::optional<TrackArtistLinkType> linkType;
	switch (user->getSubsonicArtistListMode())
	{
		case User::SubsonicArtistListMode::AllArtists:
			break;
		case User::SubsonicArtistListMode::ReleaseArtists:
			linkType = TrackArtistLinkType::ReleaseArtist;
			break;
		case User::SubsonicArtistListMode::TrackArtists:
			linkType = TrackArtistLinkType::Artist;
			break;
	}

	bool more {};
	const std::vector<Artist::pointer> artists {Artist::getByFilter(context.dbSession,
			{},
			{},
			linkType,
			Artist::SortMethod::BySortName,
			std::nullopt, more)};
	for (const Artist::pointer& artist : artists)
		indexNode.addArrayChild("artist", artistToResponseNode(user, artist, true /* id3 */));

	return response;
}

static
Response
handleGetMusicDirectoryRequest(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};

	Response response {Response::createOkResponse(context)};
	Response::Node& directoryNode {response.createNode("directory")};

	directoryNode.setAttribute("id", IdToString(id));

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	switch (id.type)
	{
		case Id::Type::Root:
		{
			directoryNode.setAttribute("name", "Music");

			bool moreResults{};
			auto artists {Artist::getAll(context.dbSession, Artist::SortMethod::BySortName, std::nullopt, moreResults)};
			for (const Artist::pointer& artist : artists)
				directoryNode.addArrayChild("child", artistToResponseNode(user, artist, false /* no id3 */));

			break;
		}

		case Id::Type::Artist:
		{
			auto artist {Artist::getById(context.dbSession, id.value)};
			if (!artist)
				throw RequestedDataNotFoundError {};

			directoryNode.setAttribute("name", makeNameFilesystemCompatible(artist->getName()));

			auto releases {artist->getReleases()};
			for (const Release::pointer& release : releases)
				directoryNode.addArrayChild("child", releaseToResponseNode(release, context.dbSession, user, false /* no id3 */));

			break;
		}

		case Id::Type::Release:
		{
			auto release {Release::getById(context.dbSession, id.value)};
			if (!release)
				throw RequestedDataNotFoundError {};

			directoryNode.setAttribute("name", makeNameFilesystemCompatible(release->getName()));

			auto tracks {release->getTracks()};
			for (const Track::pointer& track : tracks)
				directoryNode.addArrayChild("child", trackToResponseNode(track, context.dbSession, user));

			break;
		}

		default:
			throw BadParameterGenericError {"id"};
	}

	return response;
}

static
Response
handleGetMusicFoldersRequest(RequestContext& context)
{
	Response response {Response::createOkResponse(context)};
	Response::Node& musicFoldersNode {response.createNode("musicFolders")};

	Response::Node& musicFolderNode {musicFoldersNode.createArrayChild("musicFolder")};
	musicFolderNode.setAttribute("id", "0");
	musicFolderNode.setAttribute("name", "Music");

	return response;
}

static
Response
handleGetGenresRequest(RequestContext& context)
{
	Response response {Response::createOkResponse(context)};

	Response::Node& genresNode {response.createNode("genres")};

	auto transaction {context.dbSession.createSharedTransaction()};

	const ClusterType::pointer clusterType {ClusterType::getByName(context.dbSession, genreClusterName)};
	if (clusterType)
	{
		const auto clusters {clusterType->getClusters()};

		for (const Cluster::pointer& cluster : clusters)
			genresNode.addArrayChild("genre", clusterToResponseNode(cluster));
	}

	return response;
}

static
Response
handleGetIndexesRequest(RequestContext& context)
{
	Response response {Response::createOkResponse(context)};

	Response::Node& artistsNode {response.createNode("indexes")};
	artistsNode.setAttribute("ignoredArticles", "");
	artistsNode.setAttribute("lastModified", reportedDummyDateULong);

	Response::Node& indexNode {artistsNode.createArrayChild("index")};
	indexNode.setAttribute("name", "?");

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	std::optional<TrackArtistLinkType> linkType;
	switch (user->getSubsonicArtistListMode())
	{
		case User::SubsonicArtistListMode::AllArtists:
			break;
		case User::SubsonicArtistListMode::ReleaseArtists:
			linkType = TrackArtistLinkType::ReleaseArtist;
			break;
		case User::SubsonicArtistListMode::TrackArtists:
			linkType = TrackArtistLinkType::Artist;
			break;
	}

	bool more {};
	const std::vector<Artist::pointer> artists {Artist::getByFilter(context.dbSession,
			{},
			{},
			linkType,
			Artist::SortMethod::BySortName,
			std::nullopt, more)};
	for (const Artist::pointer& artist : artists)
		indexNode.addArrayChild("artist", artistToResponseNode(user, artist, false /* no id3 */));

	return response;
}

static
Response
handleGetSimilarSongsRequestCommon(RequestContext& context, bool id3)
{
	// Mandatory params
	const Id artistId {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (artistId.type != Id::Type::Artist)
		throw BadParameterGenericError {"id"};

	// Optional params
	std::size_t count {getParameterAs<std::size_t>(context.parameters, "count").value_or(50)};

	auto similarArtistIds {Service<Recommendation::IEngine>::get()->getSimilarArtists(context.dbSession,
			artistId.value,
			{TrackArtistLinkType::Artist, TrackArtistLinkType::ReleaseArtist},
			5)};

	auto transaction {context.dbSession.createSharedTransaction()};

	const Artist::pointer artist {Artist::getById(context.dbSession, artistId.value)};
	if (!artist)
		throw RequestedDataNotFoundError {};

	const User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	// "Returns a random collection of songs from the given artist and similar artists"
	auto tracks {artist->getRandomTracks(count / 2)};
	for (const Database::IdType similarArtistId : similarArtistIds)
	{
		const Artist::pointer similarArtist {Artist::getById(context.dbSession, similarArtistId)};
		if (!similarArtist)
			continue;

		auto similarArtistTracks {similarArtist->getRandomTracks((count / 2) / 5)};

		tracks.insert(std::end(tracks),
				std::make_move_iterator(std::begin(similarArtistTracks)),
				std::make_move_iterator(std::end(similarArtistTracks)));
	}

	Random::shuffleContainer(tracks);

	Response response {Response::createOkResponse(context)};
	Response::Node& similarSongsNode {response.createNode(id3 ? "similarSongs2" : "similarSongs")};
	for (const Track::pointer& track : tracks)
		similarSongsNode.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));

	return response;
}

static
Response
handleGetSimilarSongsRequest(RequestContext& context)
{
	return handleGetSimilarSongsRequestCommon(context, false /* no id3 */);
}

static
Response
handleGetSimilarSongs2Request(RequestContext& context)
{
	return handleGetSimilarSongsRequestCommon(context, true /* id3 */);
}

static
Response
handleGetStarredRequestCommon(RequestContext& context, bool id3)
{
	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node& starredNode {response.createNode(id3 ? "starred2" : "starred")};

	{
		bool moreResults {};
		const auto artists {Artist::getStarred(context.dbSession, user, {}, std::nullopt, Artist::SortMethod::BySortName, std::nullopt, moreResults)};
		for (const Artist::pointer& artist : artists)
			starredNode.addArrayChild("artist", artistToResponseNode(user, artist, id3));
	}

	{
		bool moreResults {};
		const auto releases {Release::getStarred(context.dbSession, user, {}, std::nullopt, moreResults)};
		for (const Release::pointer& release : releases)
			starredNode.addArrayChild("album", releaseToResponseNode(release, context.dbSession, user, id3));
	}

	{
		bool moreResults {};
		const auto tracks {Track::getStarred(context.dbSession, user, {}, std::nullopt, moreResults)};
		for (const Track::pointer& track : tracks)
			starredNode.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));
	}

	return response;

}

static
Response
handleGetStarredRequest(RequestContext& context)
{
	return handleGetStarredRequestCommon(context, false /* no id3 */);
}

static
Response
handleGetStarred2Request(RequestContext& context)
{
	return handleGetStarredRequestCommon(context, true /* id3 */);
}

static
Response::Node
tracklistToResponseNode(const TrackList::pointer& tracklist, Session&)
{
	Response::Node playlistNode;

	playlistNode.setAttribute("id", IdToString({Id::Type::Playlist, tracklist.id()}));
	playlistNode.setAttribute("name", tracklist->getName());
	playlistNode.setAttribute("songCount", tracklist->getCount());
	playlistNode.setAttribute("duration", std::chrono::duration_cast<std::chrono::seconds>(tracklist->getDuration()).count());
	playlistNode.setAttribute("public", tracklist->isPublic());
	playlistNode.setAttribute("created", reportedDummyDate);
	playlistNode.setAttribute("owner", tracklist->getUser()->getLoginName());

	return playlistNode;
}

static
Response
handleGetPlaylistRequest(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (id.type != Id::Type::Playlist)
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	TrackList::pointer tracklist {TrackList::getById(context.dbSession, id.value)};
	if (!tracklist)
		throw RequestedDataNotFoundError {};

	Response response {Response::createOkResponse(context)};
	Response::Node playlistNode {tracklistToResponseNode(tracklist, context.dbSession)};

	auto entries {tracklist->getEntries()};
	for (const TrackListEntry::pointer& entry : entries)
		playlistNode.addArrayChild("entry", trackToResponseNode(entry->getTrack(), context.dbSession, user));

	response.addNode("playlist", playlistNode );

	return response;
}

static
Response
handleGetPlaylistsRequest(RequestContext& context)
{
	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node& playlistsNode {response.createNode("playlists")};

	auto tracklists {TrackList::getAll(context.dbSession, user, TrackList::Type::Playlist)};
	for (const TrackList::pointer& tracklist : tracklists)
		playlistsNode.addArrayChild("playlist", tracklistToResponseNode(tracklist, context.dbSession));

	return response;
}

static
Response
handleGetSongsByGenreRequest(RequestContext& context)
{
	// Mandatory params
	std::string genre {getMandatoryParameterAs<std::string>(context.parameters, "genre")};

	// Optional params
	std::size_t size {getParameterAs<std::size_t>(context.parameters, "count").value_or(10)};
	size = std::min(size, std::size_t {500});

	std::size_t offset {getParameterAs<std::size_t>(context.parameters, "offset").value_or(0)};

	auto transaction {context.dbSession.createSharedTransaction()};

	auto clusterType {ClusterType::getByName(context.dbSession, genreClusterName)};
	if (!clusterType)
		throw RequestedDataNotFoundError {};

	auto cluster {clusterType->getCluster(genre)};
	if (!cluster)
		throw RequestedDataNotFoundError {};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node& songsByGenreNode {response.createNode("songsByGenre")};

	bool more;
	auto tracks {Track::getByFilter(context.dbSession, {cluster.id()}, {}, Range {offset, size}, more)};
	for (const Track::pointer& track : tracks)
		songsByGenreNode.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));

	return response;
}

static
Response
handleGetUserRequest(RequestContext& context)
{
	std::string username {getMandatoryParameterAs<std::string>(context.parameters, "username")};

	auto transaction {context.dbSession.createSharedTransaction()};

	checkUserIsMySelfOrAdmin(context, username);

	const User::pointer user {User::getByLoginName(context.dbSession, username)};
	if (!user)
		throw RequestedDataNotFoundError {};

	Response response {Response::createOkResponse(context)};
	response.addNode("user", userToResponseNode(user));

	return response;
}

static
Response
handleGetUsersRequest(RequestContext& context)
{
	auto transaction {context.dbSession.createSharedTransaction()};

	Response response {Response::createOkResponse(context)};
	Response::Node& usersNode {response.createNode("users")};

	const auto users {User::getAll(context.dbSession)};
	for (const User::pointer& user : users)
		usersNode.addArrayChild("user", userToResponseNode(user));

	return response;
}

static
Response
handleSearchRequestCommon(RequestContext& context, bool id3)
{
	// Mandatory params
	std::string query {getMandatoryParameterAs<std::string>(context.parameters, "query")};

	std::vector<std::string> keywords {StringUtils::splitString(query, " ")};

	// Optional params
	std::size_t artistCount {getParameterAs<std::size_t>(context.parameters, "artistCount").value_or(20)};
	std::size_t artistOffset {getParameterAs<std::size_t>(context.parameters, "artistOffset").value_or(0)};
	std::size_t albumCount {getParameterAs<std::size_t>(context.parameters, "albumCount").value_or(20)};
	std::size_t albumOffset {getParameterAs<std::size_t>(context.parameters, "albumOffset").value_or(0)};
	std::size_t songCount {getParameterAs<std::size_t>(context.parameters, "songCount").value_or(20)};
	std::size_t songOffset {getParameterAs<std::size_t>(context.parameters, "songOffset").value_or(0)};

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	Response response {Response::createOkResponse(context)};
	Response::Node& searchResult2Node {response.createNode(id3 ? "searchResult3" : "searchResult2")};

	bool more;
	{
		auto artists {Artist::getByFilter(context.dbSession, {}, keywords, std::nullopt, Artist::SortMethod::BySortName, Range {artistOffset, artistCount}, more)};
		for (const Artist::pointer& artist : artists)
			searchResult2Node.addArrayChild("artist", artistToResponseNode(user, artist, id3));
	}

	{
		auto releases {Release::getByFilter(context.dbSession, {}, keywords, Range {albumOffset, albumCount}, more)};
		for (const Release::pointer& release : releases)
			searchResult2Node.addArrayChild("album", releaseToResponseNode(release, context.dbSession, user, id3));
	}

	{
		auto tracks {Track::getByFilter(context.dbSession, {}, keywords, Range {songOffset, songCount}, more)};
		for (const Track::pointer& track : tracks)
			searchResult2Node.addArrayChild("song", trackToResponseNode(track, context.dbSession, user));
	}

	return response;
}

struct StarParameters
{
	std::vector<Id> artistIds;
	std::vector<Id> releaseIds;
	std::vector<Id> trackIds;
};

static
StarParameters
getStarParameters(const Wt::Http::ParameterMap& parameters)
{
	StarParameters res;

	std::vector<Id> ids {getMultiParametersAs<Id>(parameters, "id")};
	res.artistIds = getMultiParametersAs<Id>(parameters, "artistId");
	res.releaseIds = getMultiParametersAs<Id>(parameters, "albumId");

	if (!std::all_of(std::cbegin(res.releaseIds ), std::cend(res.releaseIds ), [](const Id& id) { return id.type == Id::Type::Release; }))
		throw BadParameterGenericError {"albumId"};

	if (!std::all_of(std::cbegin(res.artistIds ), std::cend(res.artistIds ), [](const Id& id) { return id.type == Id::Type::Artist; }))
		throw BadParameterGenericError {"artistId"};

	// Redispatch the old "id" parameter in new lists
	for (const Id& id : ids)
	{
		switch (id.type)
		{
			case Id::Type::Artist:
				res.artistIds.emplace_back(id);
				break;
			case Id::Type::Release:
				res.releaseIds.emplace_back(id);
				break;
			case Id::Type::Track:
				res.trackIds.emplace_back(id);
				break;
			default:
				throw BadParameterGenericError {"id"};
		}
	}

	return res;
}

static
Response
handleStarRequest(RequestContext& context)
{
	StarParameters params {getStarParameters(context.parameters)};

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	for (const Id& id : params.artistIds)
	{
		Artist::pointer artist {Artist::getById(context.dbSession, id.value)};
		if (!artist)
			continue;

		user.modify()->starArtist(artist);
	}

	for (const Id& id : params.releaseIds)
	{
		Release::pointer release {Release::getById(context.dbSession, id.value)};
		if (!release)
			continue;

		user.modify()->starRelease(release);
	}

	for (const Id& id : params.trackIds)
	{
		Track::pointer track {Track::getById(context.dbSession, id.value)};
		if (!track)
			continue;

		user.modify()->starTrack(track);
	}

	return Response::createOkResponse(context);
}

static
Response
handleSearch2Request(RequestContext& context)
{
	return handleSearchRequestCommon(context, false /* no id3 */);
}

static
Response
handleSearch3Request(RequestContext& context)
{
	return handleSearchRequestCommon(context, true /* id3 */);
}

static
Response
handleUnstarRequest(RequestContext& context)
{
	StarParameters params {getStarParameters(context.parameters)};

	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw RequestedDataNotFoundError {};

	for (const Id& id : params.artistIds)
	{
		Artist::pointer artist {Artist::getById(context.dbSession, id.value)};
		if (!artist)
			continue;

		user.modify()->unstarArtist(artist);
	}

	for (const Id& id : params.releaseIds)
	{
		Release::pointer release {Release::getById(context.dbSession, id.value)};
		if (!release)
			continue;

		user.modify()->unstarRelease(release);
	}

	for (const Id& id : params.trackIds)
	{
		Track::pointer track {Track::getById(context.dbSession, id.value)};
		if (!track)
			continue;

		user.modify()->unstarTrack(track);
	}


	return Response::createOkResponse(context);
}

static
Response
handleScrobble(RequestContext& context)
{
	const std::vector<Id> ids {getMandatoryMultiParametersAs<Id>(context.parameters, "id")};
	// TODO handle time in some way (need underlying refacto)

	if (!std::all_of(std::cbegin(ids), std::cend(ids), [](const Id& id) { return id.type == Id::Type::Track; }))
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw RequestedDataNotFoundError {};

	for (Id id : ids)
	{
		Track::pointer track {Track::getById(context.dbSession, id.value)};
		if (!track)
			continue;

		TrackListEntry::create(context.dbSession, track, user->getPlayedTrackList(context.dbSession));
	}

	return Response::createOkResponse(context);
}

static
Response
handleUpdateUserRequest(RequestContext& context)
{
	std::string username {getMandatoryParameterAs<std::string>(context.parameters, "username")};
	std::optional<std::string> password {getParameterAs<std::string>(context.parameters, "password")};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, username)};
	if (!user)
		throw RequestedDataNotFoundError {};

	if (password)
	{
		checkSetPasswordImplemented();

		try
		{
			Service<::Auth::IPasswordService>()->setPassword(user, decodePasswordIfNeeded(*password));
		}
		catch (const Auth::IPasswordService::PasswordTooWeakException&)
		{
			throw PasswordTooWeakGenericError {};
		}
		catch (const Auth::Exception&)
		{
			throw UserNotAuthorizedError {};
		}
	}

	return Response::createOkResponse(context);
}

static
Response
handleUpdatePlaylistRequest(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "playlistId")};
	if (id.type != Id::Type::Playlist)
		throw BadParameterGenericError {"playlistId"};

	// Optional parameters
	auto name {getParameterAs<std::string>(context.parameters, "name")};
	auto isPublic {getParameterAs<bool>(context.parameters, "public")};

	std::vector<Id> trackIdsToAdd {getMultiParametersAs<Id>(context.parameters, "songIdToAdd")};
	if (!std::all_of(std::cbegin(trackIdsToAdd), std::cend(trackIdsToAdd), [](const Id& id) { return id.type == Id::Type::Track; }))
		throw BadParameterGenericError {"songIdToAdd"};

	std::vector<std::size_t> trackPositionsToRemove {getMultiParametersAs<std::size_t>(context.parameters, "songIndexToRemove")};

	auto transaction {context.dbSession.createUniqueTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	TrackList::pointer tracklist {TrackList::getById(context.dbSession, id.value)};
	if (!tracklist
		|| tracklist->getUser() != user
		|| tracklist->getType() != TrackList::Type::Playlist)
	{
		throw RequestedDataNotFoundError {};
	}

	if (name)
		tracklist.modify()->setName(*name);

	if (isPublic)
		tracklist.modify()->setIsPublic(*isPublic);

	{
		// Remove from end to make indexes stable
		std::sort(std::begin(trackPositionsToRemove), std::end(trackPositionsToRemove), std::greater<std::size_t>());

		for (std::size_t trackPositionToRemove : trackPositionsToRemove)
		{
			auto entry {tracklist->getEntry(trackPositionToRemove)};
			if (entry)
				entry.remove();
		}
	}

	// Add tracks
	for (const Id& trackIdToAdd : trackIdsToAdd)
	{
		Track::pointer track {Track::getById(context.dbSession, trackIdToAdd.value)};
		if (!track)
			continue;

		TrackListEntry::create(context.dbSession, track, tracklist );
	}

	return Response::createOkResponse(context);
}

static
Response
handleGetBookmarks(RequestContext& context)
{
	auto transaction {context.dbSession.createSharedTransaction()};

	User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	const auto bookmarks {TrackBookmark::getByUser(context.dbSession, user)};

	Response response {Response::createOkResponse(context)};
	Response::Node& bookmarksNode {response.createNode("bookmarks")};

	for (const TrackBookmark::pointer& bookmark : bookmarks)
	{
		Response::Node bookmarkNode {trackBookmarkToResponseNode(bookmark)};
		bookmarkNode.addArrayChild("entry", trackToResponseNode(bookmark->getTrack(), context.dbSession, user));

		bookmarksNode.addArrayChild("bookmark", std::move(bookmarkNode));
	}

	return response ;
}

static
Response
handleCreateBookmark(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (id.type != Id::Type::Track)
		throw BadParameterGenericError {"id"};

	unsigned long position {getMandatoryParameterAs<unsigned long>(context.parameters, "position")};
	const std::optional<std::string> comment {getParameterAs<std::string>(context.parameters, "comment")};

	auto transaction {context.dbSession.createUniqueTransaction()};

	const User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	const Track::pointer track {Track::getById(context.dbSession, id.value)};
	if (!track)
		throw RequestedDataNotFoundError {};

	// Replace any existing bookmark
	auto bookmark {TrackBookmark::getByUser(context.dbSession, user, track)};
	if (!bookmark)
		bookmark = TrackBookmark::create(context.dbSession, user, track);

	bookmark.modify()->setOffset(std::chrono::milliseconds {position});
	if (comment)
		bookmark.modify()->setComment(*comment);

	return Response::createOkResponse(context);
}

static
Response
handleDeleteBookmark(RequestContext& context)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};
	if (id.type != Id::Type::Track)
		throw BadParameterGenericError {"id"};

	auto transaction {context.dbSession.createUniqueTransaction()};

	const User::pointer user {User::getByLoginName(context.dbSession, context.userName)};
	if (!user)
		throw UserNotAuthorizedError {};

	const Track::pointer track {Track::getById(context.dbSession, id.value)};
	if (!track)
		throw RequestedDataNotFoundError {};

	auto bookmark {TrackBookmark::getByUser(context.dbSession, user, track)};
	if (!bookmark)
		throw RequestedDataNotFoundError {};

	bookmark.remove();

	return Response::createOkResponse(context);
}

static
Response
handleNotImplemented(RequestContext&)
{
	throw NotImplementedGenericError {};
}

static
void
handleGetCoverArt(RequestContext& context, const Wt::Http::Request& /*request*/, Wt::Http::Response& response)
{
	// Mandatory params
	Id id {getMandatoryParameterAs<Id>(context.parameters, "id")};

	std::size_t size {getParameterAs<std::size_t>(context.parameters, "size").value_or(256)};
	size = clamp(size, std::size_t {32}, std::size_t {1024});

	std::shared_ptr<CoverArt::IEncodedImage> cover;
	switch (id.type)
	{
		case Id::Type::Track:
			cover = Service<CoverArt::IGrabber>::get()->getFromTrack(context.dbSession, id.value, size);
			break;
		case Id::Type::Release:
			cover = Service<CoverArt::IGrabber>::get()->getFromRelease(context.dbSession, id.value, size);
			break;
		default:
			throw BadParameterGenericError {"id"};
	}

	response.out().write(reinterpret_cast<const char*>(cover->getData()), cover->getDataSize());
	response.setMimeType(std::string {cover->getMimeType()});
}

using RequestHandlerFunc = std::function<Response(RequestContext& context)>;
using CheckImplementedFunc = std::function<void()>;
struct RequestEntryPointInfo
{
	RequestHandlerFunc		func;
	bool					mustBeAdmin;
	CheckImplementedFunc	checkFunc {};
};

static std::unordered_map<std::string, RequestEntryPointInfo> requestEntryPoints
{
	// System
	{"ping",		{handlePingRequest,			false}},
	{"getLicense",		{handleGetLicenseRequest,		false}},

	// Browsing
	{"getMusicFolders",	{handleGetMusicFoldersRequest,		false}},
	{"getIndexes",		{handleGetIndexesRequest,		false}},
	{"getMusicDirectory",	{handleGetMusicDirectoryRequest,	false}},
	{"getGenres",		{handleGetGenresRequest,		false}},
	{"getArtists",		{handleGetArtistsRequest,		false}},
	{"getArtist",		{handleGetArtistRequest,		false}},
	{"getAlbum",		{handleGetAlbumRequest,			false}},
	{"getSong",		{handleNotImplemented,			false}},
	{"getVideos",		{handleNotImplemented,			false}},
	{"getArtistInfo",	{handleGetArtistInfoRequest,		false}},
	{"getArtistInfo2",	{handleGetArtistInfo2Request,		false}},
	{"getAlbumInfo",	{handleNotImplemented,			false}},
	{"getAlbumInfo2",	{handleNotImplemented,			false}},
	{"getSimilarSongs",	{handleGetSimilarSongsRequest,		false}},
	{"getSimilarSongs2",	{handleGetSimilarSongs2Request,		false}},
	{"getTopSongs",		{handleNotImplemented,			false}},

	// Album/song lists
	{"getAlbumList",	{handleGetAlbumListRequest,		false}},
	{"getAlbumList2",	{handleGetAlbumList2Request,		false}},
	{"getRandomSongs",	{handleGetRandomSongsRequest,		false}},
	{"getSongsByGenre",	{handleGetSongsByGenreRequest,		false}},
	{"getNowPlaying",	{handleNotImplemented,			false}},
	{"getStarred",		{handleGetStarredRequest,		false}},
	{"getStarred2",		{handleGetStarred2Request,		false}},

	// Searching
	{"search",		{handleNotImplemented,			false}},
	{"search2",		{handleSearch2Request,			false}},
	{"search3",		{handleSearch3Request,			false}},

	// Playlists
	{"getPlaylists",	{handleGetPlaylistsRequest,		false}},
	{"getPlaylist",		{handleGetPlaylistRequest,		false}},
	{"createPlaylist",	{handleCreatePlaylistRequest,		false}},
	{"updatePlaylist",	{handleUpdatePlaylistRequest,		false}},
	{"deletePlaylist",	{handleDeletePlaylistRequest,		false}},

	// Media retrieval
	{"hls",				{handleNotImplemented,			false}},
	{"getCaptions",		{handleNotImplemented,			false}},
	{"getLyrics",		{handleNotImplemented,			false}},
	{"getAvatar",		{handleNotImplemented,			false}},

	// Media annotation
	{"star",			{handleStarRequest,				false}},
	{"unstar",			{handleUnstarRequest,			false}},
	{"setRating",		{handleNotImplemented,			false}},
	{"scrobble",		{handleScrobble,				false}},

	// Sharing
	{"getShares",		{handleNotImplemented,			false}},
	{"createShares",	{handleNotImplemented,			false}},
	{"updateShare",		{handleNotImplemented,			false}},
	{"deleteShare",		{handleNotImplemented,			false}},

	// Podcast
	{"getPodcasts",			{handleNotImplemented,			false}},
	{"getNewestPodcasts",		{handleNotImplemented,			false}},
	{"refreshPodcasts",		{handleNotImplemented,			false}},
	{"createPodcastChannel",	{handleNotImplemented,			false}},
	{"deletePodcastChannel",	{handleNotImplemented,			false}},
	{"deletePodcastEpisode",	{handleNotImplemented,			false}},
	{"downloadPodcastEpisode",	{handleNotImplemented,			false}},

	// Jukebox
	{"jukeboxControl",	{handleNotImplemented,			false}},

	// Internet radio
	{"getInternetRadioStations",	{handleNotImplemented,			false}},
	{"createInternetRadioStation",	{handleNotImplemented,			false}},
	{"updateInternetRadioStation",	{handleNotImplemented,			false}},
	{"deleteInternetRadioStation",	{handleNotImplemented,			false}},

	// Chat
	{"getChatMessages",	{handleNotImplemented,			false}},
	{"addChatMessages",	{handleNotImplemented,			false}},

	// User management
	{"getUser",			{handleGetUserRequest,			false}},
	{"getUsers",		{handleGetUsersRequest,			true}},
	{"createUser",		{handleCreateUserRequest,		true, &checkSetPasswordImplemented}},
	{"updateUser",		{handleUpdateUserRequest,		true}},
	{"deleteUser",		{handleDeleteUserRequest,		true}},
	{"changePassword",	{handleChangePassword,			false, &checkSetPasswordImplemented}},

	// Bookmarks
	{"getBookmarks",	{handleGetBookmarks,			false}},
	{"createBookmark",	{handleCreateBookmark,			false}},
	{"deleteBookmark",	{handleDeleteBookmark,			false}},
	{"getPlayQueue",	{handleNotImplemented,			false}},
	{"savePlayQueue",	{handleNotImplemented,			false}},

	// Media library scanning
	{"getScanStatus",	{Scan::handleGetScanStatus,		true}},
	{"startScan",		{Scan::handleStartScan,			true}},
};

using MediaRetrievalHandlerFunc = std::function<void(RequestContext&, const Wt::Http::Request&, Wt::Http::Response&)>;
static std::unordered_map<std::string, MediaRetrievalHandlerFunc> mediaRetrievalHandlers
{
	// Media retrieval
	{"download",		Stream::handleDownload},
	{"stream",			Stream::handleStream},
	{"getCoverArt",		handleGetCoverArt},
};

void
SubsonicResource::handleRequest(const Wt::Http::Request &request, Wt::Http::Response &response)
{
	static std::atomic<std::size_t> curRequestId {};

	const std::size_t requestId {curRequestId++};

	LMS_LOG(API_SUBSONIC, DEBUG) << "Handling request " << requestId << " '" << request.pathInfo() << "', continuation = " << (request.continuation() ? "true" : "false") << ", params = " << parameterMapToDebugString(request.getParameterMap());

	std::string requestPath {request.pathInfo()};
	if (StringUtils::stringEndsWith(requestPath, ".view"))
		requestPath.resize(requestPath.length() - 5);

	const Wt::Http::ParameterMap& parameters {request.getParameterMap()};

	// Optional parameters
	const ResponseFormat format {getParameterAs<std::string>(parameters, "f").value_or("xml") == "json" ? ResponseFormat::json : ResponseFormat::xml};

	std::string clientName;

	try
	{
		// Mandatory parameters
		const ClientInfo clientInfo {getClientInfo(parameters)};

		clientName = clientInfo.name;

		Session& dbSession {_db.getTLSSession()};

		const Auth::IPasswordService::CheckResult checkResult {Service<Auth::IPasswordService>::get()->checkUserPassword(dbSession,
																	boost::asio::ip::address::from_string(request.clientAddress()),
																	clientInfo.user, clientInfo.password)};

		switch (checkResult.state)
		{
			case Auth::IPasswordService::CheckResult::State::Granted:
				break;
			case Auth::IPasswordService::CheckResult::State::Denied:
				throw WrongUsernameOrPasswordError {};
			case Auth::IPasswordService::CheckResult::State::Throttled:
				throw LoginThrottledGenericError {};
		}

		RequestContext requestContext {parameters, dbSession, clientInfo.user, clientInfo.name};

		auto itEntryPoint {requestEntryPoints.find(requestPath)};
		if (itEntryPoint != requestEntryPoints.end())
		{
			if (itEntryPoint->second.checkFunc)
				itEntryPoint->second.checkFunc();

			if (itEntryPoint->second.mustBeAdmin)
			{
				auto transaction {dbSession.createSharedTransaction()};

				User::pointer user {User::getByLoginName(dbSession, clientInfo.user)};
				if (!user || !user->isAdmin())
					throw UserNotAuthorizedError {};
			}

			Response resp {(itEntryPoint->second.func)(requestContext)};

			resp.write(response.out(), format);
			response.setMimeType(ResponseFormatToMimeType(format));

			LMS_LOG(API_SUBSONIC, DEBUG) << "Request " << requestId << " '" << requestPath << "' handled!";
			return;
		}

		auto itStreamHandler {mediaRetrievalHandlers.find(requestPath)};
		if (itStreamHandler != mediaRetrievalHandlers.end())
		{
			itStreamHandler->second(requestContext, request, response);
			LMS_LOG(API_SUBSONIC, DEBUG) << "Request " << requestId  << " '" << requestPath << "' handled!";
			return;
		}

		LMS_LOG(API_SUBSONIC, ERROR) << "Unhandled command '" << requestPath << "'";
		throw UnknownEntryPointGenericError {};
	}
	catch (const Error& e)
	{
		LMS_LOG(API_SUBSONIC, ERROR) << "Error while processing request '" << requestPath << "'"
			<< ", params = [" << parameterMapToDebugString(request.getParameterMap()) << "]"
			<< ", code = " << static_cast<int>(e.getCode()) << ", msg = '" << e.getMessage() << "'";
		Response resp {Response::createFailedResponse(clientName, e)};
		resp.write(response.out(), format);
		response.setMimeType(ResponseFormatToMimeType(format));
	}
}

} // namespace api::subsonic

