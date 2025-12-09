using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthenAPI.Controllers;

/// <summary>
/// API Controller for Active Directory LDAPS operations
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class LdapController : ControllerBase
{
    private readonly ILdapService _ldapService;
    private readonly ILogger<LdapController> _logger;

    public LdapController(ILdapService ldapService, ILogger<LdapController> logger)
    {
        _ldapService = ldapService;
        _logger = logger;
    }

    /// <summary>
    /// Test connection to Active Directory server
    /// </summary>
    /// <returns>Connection status</returns>
    [HttpGet("test-connection")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> TestConnection()
    {
        _logger.LogInformation("Testing LDAP connection");

        var isConnected = await _ldapService.TestConnectionAsync();

        if (isConnected)
        {
            return Ok(ApiResponse.Ok("Successfully connected to Active Directory"));
        }

        return StatusCode(StatusCodes.Status503ServiceUnavailable,
            ApiResponse.Fail("Failed to connect to Active Directory"));
    }

    /// <summary>
    /// Authenticate a user against Active Directory
    /// </summary>
    /// <param name="request">Authentication credentials</param>
    /// <returns>User information if authentication successful</returns>
    [HttpPost("authenticate")]
    [ProducesResponseType(typeof(ApiResponse<UserInfo>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Authenticate([FromBody] AuthenticateRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ApiResponse.Fail("Invalid request",
                string.Join("; ", ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage)))));
        }

        _logger.LogInformation("Authentication attempt for user: {Username}", request.Username);

        var userInfo = await _ldapService.AuthenticateAsync(request.Username, request.Password);

        if (userInfo != null)
        {
            _logger.LogInformation("User authenticated successfully: {Username}", request.Username);
            return Ok(ApiResponse<UserInfo>.Ok(userInfo, "Authentication successful"));
        }

        _logger.LogWarning("Authentication failed for user: {Username}", request.Username);
        return Unauthorized(ApiResponse.Fail("Authentication failed. Invalid username or password."));
    }

    /// <summary>
    /// Get user information by username
    /// </summary>
    /// <param name="username">Username (sAMAccountName or UPN)</param>
    /// <returns>User information</returns>
    [HttpGet("users/{username}")]
    [ProducesResponseType(typeof(ApiResponse<UserInfo>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUser(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(ApiResponse.Fail("Username is required"));
        }

        _logger.LogInformation("Getting user info for: {Username}", username);

        var userInfo = await _ldapService.GetUserAsync(username);

        if (userInfo != null)
        {
            return Ok(ApiResponse<UserInfo>.Ok(userInfo));
        }

        return NotFound(ApiResponse.Fail($"User '{username}' not found"));
    }

    /// <summary>
    /// Search users in Active Directory
    /// </summary>
    /// <param name="request">Search parameters</param>
    /// <returns>List of matching users</returns>
    [HttpPost("users/search")]
    [ProducesResponseType(typeof(ApiResponse<List<UserInfo>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> SearchUsers([FromBody] SearchRequest request)
    {
        _logger.LogInformation("Searching users with query: {Query}", request.Query);

        var users = await _ldapService.SearchUsersAsync(request);

        return Ok(ApiResponse<List<UserInfo>>.Ok(users, $"Found {users.Count} user(s)"));
    }

    /// <summary>
    /// Search users using query string parameter
    /// </summary>
    /// <param name="q">Search query</param>
    /// <param name="maxResults">Maximum results (default: 100)</param>
    /// <returns>List of matching users</returns>
    [HttpGet("users/search")]
    [ProducesResponseType(typeof(ApiResponse<List<UserInfo>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> SearchUsersGet(
        [FromQuery] string? q = null,
        [FromQuery] int maxResults = 100)
    {
        var request = new SearchRequest
        {
            Query = q,
            MaxResults = maxResults
        };

        _logger.LogInformation("Searching users with query: {Query}", q);

        var users = await _ldapService.SearchUsersAsync(request);

        return Ok(ApiResponse<List<UserInfo>>.Ok(users, $"Found {users.Count} user(s)"));
    }

    /// <summary>
    /// Get groups for a user
    /// </summary>
    /// <param name="username">Username</param>
    /// <returns>List of group names</returns>
    [HttpGet("users/{username}/groups")]
    [ProducesResponseType(typeof(ApiResponse<List<string>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserGroups(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(ApiResponse.Fail("Username is required"));
        }

        _logger.LogInformation("Getting groups for user: {Username}", username);

        // First check if user exists
        var userInfo = await _ldapService.GetUserAsync(username);
        if (userInfo == null)
        {
            return NotFound(ApiResponse.Fail($"User '{username}' not found"));
        }

        var groups = await _ldapService.GetUserGroupsAsync(username);

        return Ok(ApiResponse<List<string>>.Ok(groups, $"User belongs to {groups.Count} group(s)"));
    }

    /// <summary>
    /// Check if user is member of a specific group
    /// </summary>
    /// <param name="username">Username</param>
    /// <param name="groupName">Group name</param>
    /// <returns>Membership status</returns>
    [HttpGet("users/{username}/groups/{groupName}/membership")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> CheckGroupMembership(string username, string groupName)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(ApiResponse.Fail("Username is required"));
        }

        if (string.IsNullOrWhiteSpace(groupName))
        {
            return BadRequest(ApiResponse.Fail("Group name is required"));
        }

        _logger.LogInformation("Checking if user {Username} is member of group {GroupName}", username, groupName);

        // First check if user exists
        var userInfo = await _ldapService.GetUserAsync(username);
        if (userInfo == null)
        {
            return NotFound(ApiResponse.Fail($"User '{username}' not found"));
        }

        var isMember = await _ldapService.IsUserInGroupAsync(username, groupName);

        var message = isMember
            ? $"User '{username}' is a member of group '{groupName}'"
            : $"User '{username}' is NOT a member of group '{groupName}'";

        return Ok(ApiResponse<bool>.Ok(isMember, message));
    }
}
