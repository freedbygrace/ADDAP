Declare @OperatingSystemFilter VARCHAR(Max) = '%NT%Workstation%';
Declare @IsVirtualMachine INT = 0;
Declare @Manufacturer VARCHAR(Max) = '%';
Declare @NullReplacementValue VARCHAR(Max) = 'N/A';

Select Distinct
    dbo.v_GS_MS_SYSTEMINFORMATION.BaseBoardProduct0 As 'BaseboardProduct',
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemFamily0 As 'SystemFamily',
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemManufacturer0 As 'SystemManufacturer',
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemProductName0 As 'SystemProductName',
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemSKU0 As 'SystemSKU',
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemVersion0 As 'SystemVersion'
From
    dbo.v_R_System
		Inner Join dbo.v_GS_MS_SYSTEMINFORMATION On (dbo.v_R_System.ResourceID = dbo.v_GS_MS_SYSTEMINFORMATION.ResourceID)
Where
	(dbo.v_R_System.Operating_System_Name_and0 Like @OperatingSystemFilter)
		And
	(dbo.v_R_System.Is_Virtual_Machine0 = @IsVirtualMachine)
		And
	((dbo.v_GS_MS_SYSTEMINFORMATION.SystemManufacturer0 Like @Manufacturer))
Order By
    dbo.v_GS_MS_SYSTEMINFORMATION.SystemManufacturer0