CREATE PROCEDURE [dbo].[OrganizationUser_ReadCountByOrganizationId]
    @OrganizationId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON

    SELECT
        COUNT(1)
    FROM
        [dbo].[OrganizationUser]
    WHERE
        [OrganizationId] = @OrganizationId
        AND [Disabled] = 0
END