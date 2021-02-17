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

#include "PasswordServiceBase.hpp"

#include "internal/InternalPasswordService.hpp"
#ifdef LMS_SUPPORT_PAM
#include "pam/PAMPasswordService.hpp"
#endif // LMS_SUPPORT_PAM

#include "auth/Types.hpp"
#include "database/Session.hpp"
#include "utils/Exception.hpp"
#include "utils/Logger.hpp"

namespace Auth {

	std::unique_ptr<IPasswordService>
	createPasswordServiceBase(std::string_view passwordAuthenticationBackend, std::size_t maxThrottlerEntries)
	{
		if (passwordAuthenticationBackend == "internal")
			return std::make_unique<InternalPasswordService>(maxThrottlerEntries);
#ifdef LMS_SUPPORT_PAM
		else if (passwordAuthenticationBackend == "PAM")
			return std::make_unique<PAMPasswordService>(maxThrottlerEntries);
#endif // LMS_SUPPORT_PAM

		throw Exception {"Unhandled password authentication backend!"};
	}

	PasswordServiceBase::PasswordServiceBase(std::size_t maxThrottlerEntries)
		: _loginThrottler {maxThrottlerEntries}
	{
	}

	PasswordServiceBase::CheckResult
	PasswordServiceBase::checkUserPassword(Database::Session& session,
			const boost::asio::ip::address& clientAddress,
			std::string_view loginName,
			std::string_view password)
	{
		// Do not waste too much resource on brute force attacks (optim)
		{
			std::shared_lock lock {_mutex};

			if (_loginThrottler.isClientThrottled(clientAddress))
				return {CheckResult::State::Throttled};
		}

		const bool match {checkUserPassword(session, loginName, password)};
		{
			std::unique_lock lock {_mutex};

			if (_loginThrottler.isClientThrottled(clientAddress))
				return {CheckResult::State::Throttled};

			if (match)
			{
				_loginThrottler.onGoodClientAttempt(clientAddress);

				auto transaction {session.createSharedTransaction()};

				const Database::User::pointer user {Database::User::getByLoginName(session, loginName)};
				if (!user)
					return {CheckResult::State::Denied};

				return {CheckResult::State::Granted, user.id()};
			}
			else
			{
				_loginThrottler.onBadClientAttempt(clientAddress);
				return {CheckResult::State::Denied};
			}
		}
	}

} // namespace Auth

