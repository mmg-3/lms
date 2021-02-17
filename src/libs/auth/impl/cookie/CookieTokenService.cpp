/*
 * Copyright (C) 2019 Emeric Poupon
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

#include "CookieTokenService.hpp"

#include <Wt/Auth/HashFunction.h>
#include <Wt/Auth/PasswordStrengthValidator.h>
#include <Wt/WRandom.h>

#include "database/Session.hpp"
#include "database/User.hpp"
#include "utils/Exception.hpp"
#include "utils/Logger.hpp"

namespace
{
	struct AuthTokenInfo
	{
		Database::IdType userId;
		Wt::WDateTime expiry;
	};

	std::optional<CookieTokenService::CheckResult::AuthTokenInfo>
	processAuthToken(Database::Session& session, const std::string& secret)
	{
		const std::string secretHash {sha1Function.compute(secret, {})};

		auto transaction {session.createUniqueTransaction()};

		Database::AuthToken::pointer authToken {Database::AuthToken::getByValue(session, secretHash)};
		if (!authToken)
			return std::nullopt;

		if (authToken->getExpiry() < Wt::WDateTime::currentDateTime())
		{
			authToken.remove();
			return std::nullopt;
		}

		LMS_LOG(UI, DEBUG) << "Found auth token for user '" << authToken->getUser()->getLoginName() << "'!";

		CookieTokenService::AuthTokenProcessResult::AuthTokenInfo res {authToken->getUser().id(), authToken->getExpiry()};
		authToken.remove();

		return res;
	}
}

namespace Auth
{

static const Wt::Auth::SHA1HashFunction sha1Function;

CookieTokenService::CookieTokenService(std::size_t maxThrottlerEntries)
: _loginThrottler {maxThrottlerEntries}
{
}

std::string
CookieTokenService::createAuthToken(Database::Session& session, Database::IdType userId, const Wt::WDateTime& expiry)
{
	const std::string secret {Wt::WRandom::generateId(32)};
	const std::string secretHash {sha1Function.compute(secret, {})};

	auto transaction {session.createUniqueTransaction()};

	Database::User::pointer user {Database::User::getById(session, userId)};
	if (!user)
		throw Exception {"User deleted"};

	Database::AuthToken::pointer authToken {Database::AuthToken::create(session, secretHash, expiry, user)};

	LMS_LOG(UI, DEBUG) << "Created auth token for user '" << user->getLoginName() << "', expiry = " << expiry.toString();

	// Remove some outdated tokens manually as the user may connect from no longer used places
	if (user->getAuthTokensCount() >= 50)
		Database::AuthToken::removeExpiredTokens(session, Wt::WDateTime::currentDateTime());

	return secret;
}



CookieTokenService::AuthTokenProcessResult
CookieTokenService::processAuthToken(Database::Session& session, const boost::asio::ip::address& clientAddress, const std::string& tokenValue)
{
	// Do not waste too much resource on brute force attacks (optim)
	{
		std::shared_lock lock {_mutex};

		if (_loginThrottler.isClientThrottled(clientAddress))
			return AuthTokenProcessResult {AuthTokenProcessResult::State::Throttled};
	}

	auto res {Auth::processAuthToken(session, tokenValue)};
	{
		std::unique_lock lock {_mutex};

		if (_loginThrottler.isClientThrottled(clientAddress))
			return AuthTokenProcessResult {AuthTokenProcessResult::State::Throttled};

		if (!res)
		{
			_loginThrottler.onBadClientAttempt(clientAddress);
			return AuthTokenProcessResult {AuthTokenProcessResult::State::NotFound};
		}

		_loginThrottler.onGoodClientAttempt(clientAddress);
		return AuthTokenProcessResult {AuthTokenProcessResult::State::Found, std::move(*res)};
	}
}

std::optional<Database::IdType>
CookieTokenService::processAuthToken(Database::Session& session, Wt::WApplication& app, const Wt::WEnvironment& env)
{
	static const std::string authCookieName {"LmsAuth"};

	const std::string* authCookie {env.getCookie(authCookieName)};
	if (!authCookie)
		return std::nullopt;

	const auto res {processAuthToken(session, boost::asio::ip::address::from_string(env.clientAddress()), *authCookie)};
	switch (res.state)
	{
		case ::Auth::ICookieTokenService::CheckResult::State::NotFound:
		case ::Auth::ICookieTokenService::CheckResult::State::Throttled:
			app.setCookie(authCookieName, std::string {}, 0, "", "", env.urlScheme() == "https");
			return std::nullopt;

		case ::Auth::ICookieTokenService::CheckResult::State::Found:
		{
			const std::string secret {createAuthToken(LmsApp->getDbSession(), userId, expiry)};

			app.setCookie(authCookieName,
					secret,
					expiry.toTime_t() - Wt::WDateTime::currentDateTime().toTime_t(),
					"",
					"",
					LmsApp->environment().urlScheme() == "https");
			break;
		}
	}

	return res.authTokenInfo->userId;
}


} // namespace Auth

