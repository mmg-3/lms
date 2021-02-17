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

#pragma once

#include <shared_mutex>
#include <boost/asio/ip/address.hpp>
#include <Wt/WDateTime.h>

#include "auth/ITokenService.hpp"

#include "LoginThrottler.hpp"

namespace Auth
{
	class CookieTokenService : public ITokenService
	{
		public:
			CookieTokenService(std::size_t maxThrottlerEntries);

			CookieTokenService(const CookieTokenService&) = delete;
			CookieTokenService& operator=(const CookieTokenService&) = delete;
			CookieTokenService(CookieTokenService&&) = delete;
			CookieTokenService& operator=(CookieTokenService&&) = delete;

		private:
			CheckResult		checkUser(Database::Session& session, Wt::WApplication& app) override;
			void			logoutUser(Database::Session& session, Wt::WApplication& app, Database::IdType userid) override;

			CheckResult		processAuthToken(Database::Session& session, const boost::asio::ip::address& clientAddress, const std::string& tokenValue);
			std::string		createAuthToken(Database::Session& session, Database::IdType userid, const Wt::WDateTime& expiry);

			std::shared_mutex	_mutex;
			LoginThrottler		_loginThrottler;
	};
}

