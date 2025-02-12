namespace AuthTest.Factories;

public interface IAccessTokenFactory
{
    string GenerateAccessTokenForUser(string userId);

    string GenerateTokenForExternalUser(string oAuthId, string externalProvider);
}