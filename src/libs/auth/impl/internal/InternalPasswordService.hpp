/*
 * Copyright (C) 2021 Emeric Poupon
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

#include <Wt/Auth/HashFunction.h>
#include <Wt/Auth/PasswordStrengthValidator.h>

#include "database/User.hpp"
#include "PasswordServiceBase.hpp"
#include "LoginThrottler.hpp"

namespace Auth
{

	class InternalPasswordService : public PasswordServiceBase
	{
		public:
			InternalPasswordService(std::size_t maxThrottlerEntries);

		private:

			bool	checkUserPassword(Database::Session& session,
						std::string_view loginName,
						std::string_view password) override;

			bool	canSetPasswords() const override;
			bool	isPasswordSecureEnough(std::string_view loginName, std::string_view password) const override;
			void	setPassword(Wt::Dbo::ptr<Database::User> user, std::string_view newPassword) override;

			Database::User::PasswordHash	hashPassword(std::string_view password) const;
			void							hashRandomPassword() const;

			const Wt::Auth::BCryptHashFunction	_hashFunc {7}; // TODO parametrize this
			Wt::Auth::PasswordStrengthValidator	_validator;
	};

}
